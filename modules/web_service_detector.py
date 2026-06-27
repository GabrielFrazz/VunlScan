import logging
import subprocess
import shutil
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import socket

logger = logging.getLogger(__name__)

def detect_web_services(target: str, logger_param: logging.Logger, timeout: int = 30) -> Dict:
    """Detecta serviços web num target via nmap"""
    log = logger_param

    log.debug(f"Detectando serviços web em {target}")
    
    web_ports = [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9000]
    detected_services = []
    
    # Verifica se nmap está disponível
    if not shutil.which('nmap'):
        log.warning("nmap não encontrado — tentando detecção via socket")
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
            'method': 'socket_fallback'
        }

    try:
        ports_str = ','.join(map(str, web_ports))
        # Sem shell=True — lista de argumentos para evitar injeção de comandos
        cmd_list = ['nmap', '-Pn', '-T4', '-p', ports_str, '--script', 'http-title', target]
        cmd_str = ' '.join(cmd_list)
        
        result = subprocess.run(
            cmd_list,
            shell=False,
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
        
        # Fallback via socket se nmap não encontrou nada
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
        log.warning(f"Timeout na detecção de serviços web para {target}")
        return {
            'target': target,
            'web_services': [],
            'has_web_services': False,
            'error': f'timeout after {timeout}s',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        log.error(f"Erro na detecção de serviços web para {target}: {str(e)}")
        return {
            'target': target,
            'web_services': [],
            'has_web_services': False,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def test_port_socket(target: str, port: int, timeout: int = 5) -> bool:
    """Testa se uma porta está aberta via socket TCP direto"""
    try:
        # getaddrinfo suporta IPv4, IPv6 e hostnames
        infos = socket.getaddrinfo(target, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for af, socktype, proto, canonname, sockaddr in infos:
            sock = socket.socket(af, socktype)
            sock.settimeout(timeout)
            result = sock.connect_ex(sockaddr)
            sock.close()
            if result == 0:
                return True
        return False
    except Exception:
        return False

def get_web_urls(target: str, web_services: List[Dict]) -> List[str]:
    """Gera URLs a partir dos serviços web detectados"""
    urls = []
    
    if not web_services:
        # Nenhum serviço detectado: retorna lista vazia em vez de URLs genéricas
        return urls
    
    for service in web_services:
        protocol = service.get('protocol', 'http')
        port = service.get('port')
        
        if port in [80, 443]:
            # Portas padrão — não precisa especificar
            urls.append(f"{protocol}://{target}")
        else:
            # Portas não padrão
            urls.append(f"{protocol}://{target}:{port}")
    
    return urls

def should_run_web_scanner(target: str, logger_param: logging.Logger) -> Tuple[bool, List[str]]:
    """Verifica se o target tem serviços web e retorna URLs para scan"""
    log = logger_param
    
    # Se o alvo já é uma URL explícita (ex: teste web focado), pula a varredura Nmap e aceita direto
    if target.startswith('http://') or target.startswith('https://'):
        log.info(f"Alvo {target} já é uma URL explícita. Pulando detecção Nmap.")
        return True, [target]
    
    detection_result = detect_web_services(target, log)
    
    if detection_result.get('has_web_services', False):
        web_services = detection_result.get('web_services', [])
        urls = get_web_urls(target, web_services)
        if urls:
            log.info(f"Serviços web detectados em {target}. URLs para scan: {urls}")
            return True, urls
    
    log.info(f"Nenhum serviço web detectado em {target}. Pulando scanners web.")
    return False, []
