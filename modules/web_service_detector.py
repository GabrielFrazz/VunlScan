import logging
import subprocess
import socket
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

def detect_web_services(target: str, logger_param: logging.Logger, timeout: int = 30) -> Dict:

    global logger
    logger = logger_param
    
    logger.debug(f"Detectando serviços web em {target}")
    
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
    detected_services = []
    
    try:
        ports_str = ','.join(map(str, web_ports))
        cmd = f"nmap -Pn -T4 -p {ports_str} --script http-title {target}"
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=timeout
        )
        
        if result.returncode == 0:
            lines = result.stdout.split('\n')
            current_port = None
            
            for line in lines:
                line = line.strip()
                
                if '/tcp' in line and 'open' in line:
                    parts = line.split('/')
                    if len(parts) > 0:
                        port = parts[0].strip()
                        if port.isdigit() and int(port) in web_ports:
                            current_port = int(port)
                            service_info = {
                                'port': current_port,
                                'protocol': 'https' if current_port in [443, 8443] else 'http',
                                'service': 'web',
                                'title': None,
                                'server': None
                            }
                            detected_services.append(service_info)
                
                elif '|_http-title:' in line and current_port:
                    title = line.split('|_http-title:')[1].strip()
                    if detected_services:
                        detected_services[-1]['title'] = title
        
        if not detected_services:
            for port in [80, 443]:
                if test_port_socket(target, port, timeout=5):
                    detected_services.append({
                        'port': port,
                        'protocol': 'https' if port == 443 else 'http',
                        'service': 'web',
                        'title': None,
                        'server': None,
                        'method': 'socket_test'
                    })
        
        return {
            'target': target,
            'web_services': detected_services,
            'has_web_services': len(detected_services) > 0,
            'timestamp': datetime.now().isoformat(),
            'method': 'nmap_web_detection'
        }
        
    except subprocess.TimeoutExpired:
        logger.warning(f"Timeout na detecção de serviços web para {target}")
        return {
            'target': target,
            'web_services': [],
            'has_web_services': False,
            'error': f'timeout after {timeout}s',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erro na detecção de serviços web para {target}: {str(e)}")
        return {
            'target': target,
            'web_services': [],
            'has_web_services': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def test_port_socket(target: str, port: int, timeout: int = 5) -> bool:

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        sock.close()
        return result == 0
    except Exception:
        return False

def get_web_urls(target: str, web_services: List[Dict]) -> List[str]:

    urls = []
    
    if not web_services:
        urls.extend([f"http://{target}", f"https://{target}"])
    else:
        for service in web_services:
            protocol = service.get('protocol', 'http')
            port = service.get('port')
            
            if port in [80, 443]:
                # Portas padrão, não precisa especificar
                urls.append(f"{protocol}://{target}")
            else:
                # Portas não padrão, especificar na URL
                urls.append(f"{protocol}://{target}:{port}")
    
    return urls

def should_run_web_scanner(target: str, logger_param: logging.Logger) -> Tuple[bool, List[str]]:

    global logger
    logger = logger_param
    
    # Detecta serviços web
    detection_result = detect_web_services(target, logger_param)
    
    if detection_result.get('has_web_services', False):
        web_services = detection_result.get('web_services', [])
        urls = get_web_urls(target, web_services)
        logger.info(f"Serviços web detectados em {target}. URLs para scan: {urls}")
        return True, urls
    else:
        logger.info(f"Nenhum serviço web detectado em {target}. Pulando scanners web.")
        return False, []

def is_likely_web_target(target: str) -> bool:
    web_indicators = [
        'www.', '.com', '.org', '.net', '.edu', '.gov',
        'http://', 'https://', ':80', ':443', ':8080', ':8443'
    ]
    
    target_lower = target.lower()
    return any(indicator in target_lower for indicator in web_indicators)

