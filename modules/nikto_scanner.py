import logging
import subprocess
import shutil
from datetime import datetime
from typing import Dict, List, Optional
from .web_service_detector import should_run_web_scanner
import tempfile
import os

logger = logging.getLogger(__name__)

def run_nikto_scan(target: str, nikto_config: Dict, logger_param: logging.Logger,
                   web_urls: Optional[List[str]] = None) -> Dict:
    """
    Executa scan com Nikto com detecção inteligente de serviços web.

    Args:
        target: IP ou hostname do alvo
        nikto_config: Configuração do Nikto
        logger_param: Logger para uso na thread atual (sem global para evitar race condition)
        web_urls: URLs web já detectadas (evita detecção duplicada quando chamado via suite).
                  Se None, realiza detecção própria.
    """
    log = logger_param

    log.info(f"Iniciando scan Nikto no target: {target}")

    if not nikto_config.get("enabled", False):
        log.warning(f"Nikto desabilitado ou não configurado para o target {target}")
        return {"tool": "nikto", "target": target, "error": "Ferramenta desabilitada na configuração"}

    # Verifica se nikto está instalado
    if not shutil.which('nikto'):
        log.error("nikto não encontrado no PATH. Instale com: sudo apt install nikto")
        return {"tool": "nikto", "target": target, "skipped": True, "reason": "nikto não encontrado no sistema"}

    # Usa URLs fornecidas ou realiza detecção própria (uso standalone)
    if web_urls is not None:
        should_run = len(web_urls) > 0
        urls_to_scan = web_urls
    else:
        should_run, urls_to_scan = should_run_web_scanner(target, log)

    if not should_run or not urls_to_scan:
        log.info(f"Nikto pulado para {target} - nenhum serviço web detectado")
        return {
            "tool": "nikto",
            "target": target,
            "skipped": True,
            "reason": "Nenhum serviço web detectado",
            "timestamp": datetime.now().isoformat()
        }

    results = []
    timeout = nikto_config.get("max_time", 600)
    custom_flags = nikto_config.get("custom_flags", [])
    
    for url in urls_to_scan:
        output_file = None
        try:
            log.info(f"Executando Nikto em: {url}")
            
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, suffix='.txt', encoding='utf-8') as tmp_file:
                output_file = tmp_file.name

            cmd_parts = [
                'nikto',
                '-h', url,
                '-Format', 'txt',
                '-o', output_file
            ]
            if custom_flags:
                cmd_parts.extend(custom_flags)
            
            cmd_str = ' '.join(cmd_parts)
            log.info(f"Executando comando Nikto: {cmd_str}")
            log.info(f"Timeout Nikto configurado: {timeout}s")

            start_time = datetime.now()
            # Sem shell=True — cmd_parts é uma lista
            result = subprocess.run(
                cmd_parts,
                shell=False,
                capture_output=True,
                text=True,
                errors='ignore',
                timeout=timeout
            )
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            # Lê o arquivo de saída gerado pelo Nikto
            stdout_content = ""
            try:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    stdout_content = f.read()
            except FileNotFoundError:
                log.warning(f"Arquivo de saída do Nikto não encontrado: {output_file}. Usando stdout.")
                stdout_content = result.stdout  # Fallback para stdout capturado
            
            url_result = {
                'url': url,
                'command': cmd_str,
                'returncode': result.returncode,
                'stdout': stdout_content,
                'stderr': result.stderr,
                'elapsed_time': elapsed_time,
                'parsed': parse_nikto_results(stdout_content, log)
            }
            
            results.append(url_result)
            log.info(f"Scan Nikto em {url} concluído em {elapsed_time:.2f}s")
            
        except subprocess.TimeoutExpired:
            log.error(f"Timeout ({timeout}s) no scan Nikto para {url}")
            results.append({
                'url': url,
                'error': f'timeout after {timeout}s',
                'elapsed_time': timeout
            })
        except Exception as e:
            log.error(f"Erro no scan Nikto para {url}: {str(e)}")
            results.append({
                'url': url,
                'error': str(e)
            })
        finally:
            if output_file and os.path.exists(output_file):
                try:
                    os.remove(output_file)
                except OSError:
                    pass

    total_findings = sum(len(r.get('parsed', {}).get('findings', [])) for r in results)
    
    return {
        'tool': 'nikto',
        'target': target,
        'urls_scanned': urls_to_scan,
        'results': results,
        'total_findings': total_findings,
        'timestamp': datetime.now().isoformat()
    }

def parse_nikto_results(nikto_output: str, logger_param: logging.Logger) -> Dict:
    """Parser melhorado para resultados do Nikto"""
    log = logger_param
    
    parsed = {
        'findings': [],
        'server_info': {},
        'summary': {
            'total_items_checked': 0,
            'vulnerabilities_found': 0,
            'informational_items': 0
        }
    }
    
    if not nikto_output:
        return parsed
    
    lines = nikto_output.split('\n')
    
    for line in lines:
        line = line.strip()
        
        # Informações do servidor
        if line.startswith('+ Server:'):
            parsed['server_info']['server'] = line.replace('+ Server:', '').strip()
        elif line.startswith('+ The X-XSS-Protection header'):
            parsed['server_info']['xss_protection'] = line
        elif line.startswith('+ The X-Content-Type-Options header'):
            parsed['server_info']['content_type_options'] = line
        
        # Achados de segurança — vulnerabilidades conhecidas
        elif line.startswith('+ ') and any(indicator in line.upper() for indicator in ['OSVDB', 'CVE-', 'VULNERABLE', 'EXPLOIT', 'DISCLOSURE']):
            finding = {
                'type': 'vulnerability',
                'description': line[2:].strip(),
                'severity': classify_nikto_finding(line)
            }
            parsed['findings'].append(finding)
            parsed['summary']['vulnerabilities_found'] += 1
        
        # Itens informativos
        elif line.startswith('+ ') and not line.startswith('+ Server:'):
            finding = {
                'type': 'informational',
                'description': line[2:].strip(),
                'severity': 'info'
            }
            parsed['findings'].append(finding)
            parsed['summary']['informational_items'] += 1
        
        # Estatísticas
        elif 'items checked:' in line.lower():
            try:
                items_checked = int(line.split('items checked:')[1].strip().split()[0])
                parsed['summary']['total_items_checked'] = items_checked
            except (ValueError, IndexError):
                pass
    
    return parsed

def classify_nikto_finding(finding_line: str) -> str:
    """Classifica a severidade de um achado do Nikto"""
    finding_upper = finding_line.upper()
    
    if any(indicator in finding_upper for indicator in ['EXPLOIT', 'VULNERABLE', 'CRITICAL', 'REMOTE CODE']):
        return 'high'
    elif any(indicator in finding_upper for indicator in ['CVE-', 'OSVDB', 'DISCLOSURE', 'BYPASS']):
        return 'medium'
    elif any(indicator in finding_upper for indicator in ['INFORMATION', 'BANNER', 'VERSION']):
        return 'low'
    else:
        return 'info'