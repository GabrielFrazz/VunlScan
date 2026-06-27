import logging
import subprocess
import shutil
from datetime import datetime
from typing import Dict, List, Optional
from .web_service_detector import should_run_web_scanner

logger = logging.getLogger(__name__)

def run_dirb_scan(target: str, dirb_config: Dict, logger_param: logging.Logger,
                  web_urls: Optional[List[str]] = None) -> Dict:
    """
    Executa scan com Dirb com detecção inteligente de serviços web.

    Args:
        target: IP ou hostname do alvo
        dirb_config: Configuração do Dirb
        logger_param: Logger para uso na thread atual (sem global para evitar race condition)
        web_urls: URLs web já detectadas (evita detecção duplicada quando chamado via suite).
                  Se None, realiza detecção própria.
    """
    log = logger_param

    log.info(f"Iniciando scan Dirb no target: {target}")

    if not dirb_config.get('enabled', False):
        log.warning(f"Dirb desabilitado ou não configurado para o target {target}")
        return {'tool': 'dirb', 'target': target, 'error': 'Ferramenta desabilitada na configuração'}

    # Verifica se dirb está instalado
    if not shutil.which('dirb'):
        log.error("dirb não encontrado no PATH. Instale com: sudo apt install dirb")
        return {'tool': 'dirb', 'target': target, 'skipped': True, 'reason': 'dirb não encontrado no sistema'}

    # Usa URLs fornecidas ou realiza detecção própria (uso standalone)
    if web_urls is not None:
        should_run = len(web_urls) > 0
        urls_to_scan = web_urls
    else:
        should_run, urls_to_scan = should_run_web_scanner(target, log)

    if not should_run or not urls_to_scan:
        log.info(f"Dirb pulado para {target} - nenhum serviço web detectado")
        return {
            'tool': 'dirb',
            'target': target,
            'skipped': True,
            'reason': 'Nenhum serviço web detectado',
            'timestamp': datetime.now().isoformat()
        }

    wordlist = dirb_config.get('wordlist', '/usr/share/dirb/wordlists/common.txt')
    timeout = dirb_config.get('timeout', 600)
    extensions = dirb_config.get('extensions', [])
    
    # Verifica se a wordlist existe
    if not shutil.os.path.exists(wordlist):
        fallback = '/usr/share/dirb/wordlists/common.txt'
        log.warning(f"Wordlist não encontrada: {wordlist}. Tentando fallback: {fallback}")
        wordlist = fallback
        if not shutil.os.path.exists(wordlist):
            log.error("Nenhuma wordlist disponível para Dirb")
            return {'tool': 'dirb', 'target': target, 'error': f'Wordlist não encontrada: {wordlist}'}

    all_results = []
    
    for url in urls_to_scan:
        try:
            log.info(f"Executando Dirb em: {url}")
            
            cmd_parts = ['dirb', url, wordlist, '-S']
            if extensions:
                # cada extensão precisa de seu próprio ponto
                # ['.php', '.html', '.txt'] → '.php,.html,.txt'
                ext_string = ','.join([f'.{ext.lstrip(".")}' for ext in extensions])
                cmd_parts.extend(['-X', ext_string])
            
            # Sem shell=True — lista de argumentos para evitar injeção
            cmd_str = ' '.join(cmd_parts)
            log.info(f"Executando comando Dirb: {cmd_str}")
            log.info(f"Timeout Dirb configurado: {timeout}s")
            
            start_time = datetime.now()
            result = subprocess.run(
                cmd_parts,
                shell=False,
                capture_output=True,
                text=True,
                errors='ignore',
                timeout=timeout
            )
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            url_result = {
                'url': url,
                'command': cmd_str,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'elapsed_time': elapsed_time,
                'parsed': parse_dirb_results(result.stdout, log)
            }
            
            all_results.append(url_result)
            log.info(f"Scan Dirb em {url} concluído em {elapsed_time:.2f}s")
            
        except subprocess.TimeoutExpired:
            log.error(f"Timeout ({timeout}s) no scan Dirb para {url}")
            all_results.append({
                'url': url,
                'error': f'timeout after {timeout}s',
                'elapsed_time': timeout
            })
        except Exception as e:
            log.error(f"Erro no scan Dirb para {url}: {str(e)}")
            all_results.append({'url': url, 'error': str(e)})

    total_found = sum(len(r.get('parsed', {}).get('found_paths', [])) for r in all_results)
    
    return {
        'tool': 'dirb',
        'target': target,
        'urls_scanned': urls_to_scan,
        'results': all_results,
        'total_found': total_found,
        'timestamp': datetime.now().isoformat()
    }

def parse_dirb_results(dirb_output: str, logger_param: logging.Logger) -> Dict:
    """Parser para resultados do Dirb"""
    log = logger_param
    
    parsed = {
        'found_paths': [],
        'summary': {
            'total_found': 0,
            'interesting_paths': []
        }
    }
    
    if not dirb_output:
        return parsed
    
    lines = dirb_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Linhas com paths encontrados começam com '+'
        if line.startswith('+ ') or line.startswith('==> DIRECTORY:'):
            if 'CODE:' in line:
                parts = line.split('CODE:')
                url_part = parts[0].replace('+', '').strip()
                
                try:
                    status_code = int(parts[1][:3])
                except (ValueError, IndexError):
                    status_code = 0
                
                path_info = {
                    'url': url_part,
                    'status_code': status_code
                }
                
                parsed['found_paths'].append(path_info)
                parsed['summary']['total_found'] += 1
                
                # Marca paths interessantes
                if status_code in [200, 301, 302, 401, 403]:
                    parsed['summary']['interesting_paths'].append(url_part)
            
            elif '==> DIRECTORY:' in line:
                directory = line.replace('==> DIRECTORY:', '').strip()
                parsed['found_paths'].append({
                    'url': directory,
                    'status_code': 200,
                    'type': 'directory'
                })
                parsed['summary']['total_found'] += 1
                parsed['summary']['interesting_paths'].append(directory)
    
    return parsed
