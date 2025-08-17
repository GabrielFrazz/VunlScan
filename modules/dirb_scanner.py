import logging
import subprocess
from datetime import datetime
from typing import Dict, List
from .web_service_detector import should_run_web_scanner

logger = logging.getLogger(__name__)

def run_dirb_scan(target: str, dirb_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa scan com Dirb com detecção inteligente de serviços web"""
    global logger
    logger = logger_param

    logger.info(f"Iniciando scan Dirb no target: {target}")

    if not dirb_config.get('enabled', False):
        logger.warning(f"Dirb desabilitado ou não configurado para o target {target}")
        return {'tool': 'dirb', 'target': target, 'error': 'Ferramenta desabilitada na configuração'}

    # Verifica se o target possui serviços web
    should_run, web_urls = should_run_web_scanner(target, logger_param)
    
    if not should_run:
        logger.info(f"Dirb pulado para {target} - nenhum serviço web detectado")
        return {
            'tool': 'dirb',
            'target': target,
            'skipped': True,
            'reason': 'Nenhum serviço web detectado',
            'timestamp': datetime.now().isoformat()
        }

    # Executa Dirb para cada URL detectada
    results = []
    wordlist = dirb_config.get('wordlist', '/usr/share/dirb/wordlists/common.txt')
    timeout = dirb_config.get('timeout', 600)
    extensions = dirb_config.get('extensions', [])
    
    for url in web_urls:
        try:
            logger.info(f"Executando Dirb em: {url}")
            
            cmd_parts = ['dirb', url, wordlist]
            if extensions:
                # Formata extensões corretamente para o Dirb
                ext_string = ','.join([ext.lstrip('.') for ext in extensions])
                cmd_parts.extend(['-X', f".{ext_string}"])
            
            cmd = ' '.join(cmd_parts)
            logger.info(f"Executando comando Dirb: {cmd}")
            logger.info(f"Timeout Dirb configurado: {timeout}s")
            
            start_time = datetime.now()
            result = subprocess.run(
                cmd,
                shell=True,
                capture_output=True,
                text=True,
                errors='ignore',
                timeout=timeout
            )
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            url_result = {
                'url': url,
                'command': cmd,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'elapsed_time': elapsed_time,
                'parsed': parse_dirb_results(result.stdout, logger_param)
            }
            
            results.append(url_result)
            logger.info(f"Scan Dirb em {url} concluído em {elapsed_time:.2f}s")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout ({timeout}s) no scan Dirb para {url}")
            results.append({
                'url': url,
                'error': f'timeout after {timeout}s',
                'elapsed_time': timeout
            })
        except Exception as e:
            logger.error(f"Erro no scan Dirb para {url}: {str(e)}")
            results.append({
                'url': url,
                'error': str(e)
            })

    # Consolida resultados
    total_directories = sum(len(r.get('parsed', {}).get('directories_found', [])) for r in results)
    total_files = sum(len(r.get('parsed', {}).get('files_found', [])) for r in results)
    
    return {
        'tool': 'dirb',
        'target': target,
        'urls_scanned': web_urls,
        'results': results,
        'total_directories': total_directories,
        'total_files': total_files,
        'timestamp': datetime.now().isoformat()
    }

def parse_dirb_results(dirb_output: str, logger_param: logging.Logger) -> Dict:
    """Parser melhorado para resultados do Dirb"""
    global logger
    logger = logger_param
    
    parsed = {
        'directories_found': [],
        'files_found': [],
        'summary': {
            'total_directories': 0,
            'total_files': 0,
            'interesting_files': 0
        }
    }
    
    if not dirb_output:
        return parsed
    
    lines = dirb_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Diretórios encontrados
        if line.startswith('==> DIRECTORY:'):
            directory = line.replace('==> DIRECTORY:', '').strip()
            parsed['directories_found'].append({
                'path': directory,
                'type': 'directory'
            })
            parsed['summary']['total_directories'] += 1
        
        # Arquivos encontrados (CODE:200)
        elif 'CODE:200' in line and 'SIZE:' in line:
            # Formato típico: "+ http://example.com/file.txt (CODE:200|SIZE:1234)"
            if line.startswith('+'):
                parts = line[1:].strip().split(' (CODE:200')
                if len(parts) >= 2:
                    file_path = parts[0].strip()
                    size_info = parts[1].strip()
                    
                    # Extrai tamanho se disponível
                    size = None
                    if 'SIZE:' in size_info:
                        try:
                            size = int(size_info.split('SIZE:')[1].split(')')[0])
                        except (ValueError, IndexError):
                            pass
                    
                    file_info = {
                        'path': file_path,
                        'type': 'file',
                        'status_code': 200,
                        'size': size,
                        'interesting': is_interesting_file(file_path)
                    }
                    
                    parsed['files_found'].append(file_info)
                    parsed['summary']['total_files'] += 1
                    
                    if file_info['interesting']:
                        parsed['summary']['interesting_files'] += 1
        
        # Outros códigos de status interessantes
        elif any(code in line for code in ['CODE:301', 'CODE:302', 'CODE:403', 'CODE:401']):
            if line.startswith('+'):
                parts = line[1:].strip().split(' (CODE:')
                if len(parts) >= 2:
                    file_path = parts[0].strip()
                    status_code = int(parts[1][:3])
                    
                    file_info = {
                        'path': file_path,
                        'type': 'file' if '.' in file_path.split('/')[-1] else 'directory',
                        'status_code': status_code,
                        'interesting': status_code in [301, 302, 403, 401]
                    }
                    
                    if status_code in [301, 302]:
                        parsed['directories_found'].append(file_info)
                    else:
                        parsed['files_found'].append(file_info)
                        if file_info['interesting']:
                            parsed['summary']['interesting_files'] += 1
    
    return parsed

def is_interesting_file(file_path: str) -> bool:
    """Determina se um arquivo encontrado é interessante do ponto de vista de segurança"""
    interesting_extensions = [
        '.php', '.asp', '.aspx', '.jsp', '.cgi', '.pl', '.py',
        '.config', '.conf', '.ini', '.xml', '.json',
        '.sql', '.db', '.bak', '.backup', '.old', '.tmp',
        '.log', '.txt', '.readme', '.admin', '.test'
    ]
    
    interesting_names = [
        'admin', 'login', 'config', 'database', 'backup',
        'test', 'debug', 'phpinfo', 'info', 'robots.txt',
        'sitemap.xml', '.htaccess', 'web.config'
    ]
    
    file_path_lower = file_path.lower()
    
    # Verifica extensões interessantes
    for ext in interesting_extensions:
        if file_path_lower.endswith(ext):
            return True
    
    # Verifica nomes interessantes
    for name in interesting_names:
        if name in file_path_lower:
            return True
    
    return False

