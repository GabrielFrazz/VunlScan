import logging
import subprocess
from datetime import datetime
from typing import Dict, List
from .web_service_detector import should_run_web_scanner
import tempfile
import os

logger = logging.getLogger(__name__)

def run_nikto_scan(target: str, nikto_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa scan com Nikto com detecção inteligente de serviços web"""
    global logger
    logger = logger_param

    logger.info(f"Iniciando scan Nikto no target: {target}")

    if not nikto_config.get("enabled", False):
        logger.warning(f"Nikto desabilitado ou não configurado para o target {target}")
        return {"tool": "nikto", "target": target, "error": "Ferramenta desabilitada na configuração"}

    # Verifica se o target possui serviços web
    should_run, web_urls = should_run_web_scanner(target, logger_param)
    
    if not should_run:
        logger.info(f"Nikto pulado para {target} - nenhum serviço web detectado")
        return {
            "tool": "nikto",
            "target": target,
            "skipped": True,
            "reason": "Nenhum serviço web detectado",
            "timestamp": datetime.now().isoformat()
        }

    # Executa Nikto para cada URL detectada
    results = []
    timeout = nikto_config.get("max_time", 600)
    custom_flags = nikto_config.get("custom_flags", [])
    
    for url in web_urls:
        output_file = None
        try:
            logger.info(f"Executando Nikto em: {url}")
            
            # Crie um arquivo temporário para a saída do Nikto
            with tempfile.NamedTemporaryFile(mode='w+', delete=False, encoding='utf-8') as tmp_file:
                output_file = tmp_file.name

            cmd_parts = [
                'nikto',
                '-h', url,
                '-Format', 'txt',
                '-o', output_file # Adicione esta linha para especificar o arquivo de saída
            ]
            if custom_flags:
                cmd_parts.extend(custom_flags)
            
            cmd = ' '.join(cmd_parts)
            logger.info(f"Executando comando Nikto: {cmd}")
            logger.info(f"Timeout Nikto configurado: {timeout}s")

            start_time = datetime.now()
            result = subprocess.run(
                cmd_parts, # Use cmd_parts diretamente, não a string cmd com shell=True
                capture_output=True,
                text=True,
                errors='ignore',
                timeout=timeout
            )
            elapsed_time = (datetime.now() - start_time).total_seconds()
            
            # Após a execução do subprocess.run, leia o conteúdo do arquivo temporário
            stdout_content = ""
            try:
                with open(output_file, 'r', encoding='utf-8') as f:
                    stdout_content = f.read()
            except FileNotFoundError:
                logger.error(f"Arquivo de saída do Nikto não encontrado: {output_file}")
            
            url_result = {
                'url': url,
                'command': cmd,
                'returncode': result.returncode,
                'stdout': stdout_content,
                'stderr': result.stderr,
                'elapsed_time': elapsed_time,
                'parsed': parse_nikto_results(stdout_content, logger_param)
            }
            
            results.append(url_result)
            logger.info(f"Scan Nikto em {url} concluído em {elapsed_time:.2f}s")
            
        except subprocess.TimeoutExpired:
            logger.error(f"Timeout ({timeout}s) no scan Nikto para {url}")
            results.append({
                'url': url,
                'error': f'timeout after {timeout}s',
                'elapsed_time': timeout
            })
        except Exception as e:
            logger.error(f"Erro no scan Nikto para {url}: {str(e)}")
            results.append({
                'url': url,
                'error': str(e)
            })
        finally:
            # Certifique-se de remover o arquivo temporário após a leitura
            if output_file and os.path.exists(output_file):
                os.remove(output_file)

    # Consolida resultados
    total_findings = sum(len(r.get('parsed', {}).get('findings', [])) for r in results)
    
    return {
        'tool': 'nikto',
        'target': target,
        'urls_scanned': web_urls,
        'results': results,
        'total_findings': total_findings,
        'timestamp': datetime.now().isoformat()
    }

def parse_nikto_results(nikto_output: str, logger_param: logging.Logger) -> Dict:
    """Parser melhorado para resultados do Nikto"""
    global logger
    logger = logger_param
    
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
        
        # Achados de segurança
        elif line.startswith('+ ') and any(indicator in line.upper() for indicator in ['OSVDB', 'CVE-', 'VULNERABLE', 'EXPLOIT', 'DISCLOSURE']):
            finding = {
                'type': 'vulnerability',
                'description': line[2:].strip(),  # Remove '+ '
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
    
    # Alta severidade
    if any(indicator in finding_upper for indicator in ['EXPLOIT', 'VULNERABLE', 'CRITICAL', 'REMOTE CODE']):
        return 'high'
    
    # Média severidade
    elif any(indicator in finding_upper for indicator in ['CVE-', 'OSVDB', 'DISCLOSURE', 'BYPASS']):
        return 'medium'
    
    # Baixa severidade
    elif any(indicator in finding_upper for indicator in ['INFORMATION', 'BANNER', 'VERSION']):
        return 'low'
    
    # Informativo
    else:
        return 'info'