import logging
import subprocess
import time
from datetime import datetime
from typing import Dict, Optional, List

logger = logging.getLogger(__name__)

def run_nmap_scan(target: str, nmap_config: Dict, logger_param: logging.Logger, options: Optional[str] = None, scan_type: str = 'default') -> Dict:
    """Executa scan com Nmap com diferentes níveis de intensidade"""
    global logger
    logger = logger_param # Use o logger passado como parâmetro

    logger.info(f"Iniciando scan Nmap no target: {target} (tipo: {scan_type})")

    if not nmap_config.get('enabled', False):
        logger.warning(f"Nmap desabilitado ou não configurado para o target {target}")
        return {'tool': 'nmap', 'target': target, 'error': 'Ferramenta desabilitada na configuração'}

    if not options:
        if scan_type == 'quick':
            options_list = ['-sS', '-T4', '--top-ports', '100']
            timeout = nmap_config.get('timeout_quick', 300)
        elif scan_type == 'basic':
            options_list = ['-sV', '-T4', '--top-ports', str(nmap_config.get('max_ports', '1000'))]
            timeout = nmap_config.get('timeout_basic', 600)
        elif scan_type == 'comprehensive':
            options_list = ['-sV', '-sC', '-T4', '--top-ports', str(nmap_config.get('max_ports', '1000'))]
            timeout = nmap_config.get('timeout_comprehensive', 900)
        elif scan_type == 'vuln':
            options_list = ['-sV', '-T3', '--top-ports', str(nmap_config.get('max_ports', '1000')), '--script', 'vuln']
            timeout = nmap_config.get('timeout_vuln', 1800)
        elif scan_type == 'discovery':
            # Novo tipo para descoberta de hosts
            options_list = ['-sn', '-T4']
            timeout = nmap_config.get('timeout_discovery', 300)
        else:  # default
            flags = nmap_config.get('default_flags', ['-sV', '-sC'])
            timing = nmap_config.get('timing', '-T4')
            max_ports = nmap_config.get('max_ports', '1000')
            custom_scripts = nmap_config.get('custom_scripts', [])

            options_list = flags.copy()
            if timing:
                options_list.append(timing)
            if max_ports:
                options_list.extend(['--top-ports', str(max_ports)])
            if custom_scripts:
                safe_scripts = [s for s in custom_scripts if s in ['safe', 'default', 'discovery']]
                if safe_scripts:
                    options_list.extend(['--script', ','.join(safe_scripts)])
            timeout = nmap_config.get('timeout', 900)
        options = ' '.join(options_list)
    else: # Options foram passadas diretamente
        timeout = nmap_config.get('timeout', 900) # Usa timeout padrão se options são customizadas

    try:
        cmd = f"nmap {options} {target}"
        logger.info(f"Executando comando Nmap: {cmd}")
        logger.info(f"Timeout Nmap configurado: {timeout}s")

        start_time = time.time()
        process = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors='ignore' # Adicionado para evitar UnicodeDecodeError com output do nmap
        )

        try:
            stdout, stderr = process.communicate(timeout=timeout)
            elapsed_time = time.time() - start_time
            logger.info(f"Scan Nmap em {target} concluído em {elapsed_time:.2f}s")
            return {
                'tool': 'nmap',
                'target': target,
                'command': cmd,
                'returncode': process.returncode,
                'stdout': stdout,
                'stderr': stderr,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time': elapsed_time,
                'scan_type': scan_type
            }
        except subprocess.TimeoutExpired:
            logger.warning(f"Timeout ({timeout}s) no scan Nmap para {target}")
            process.kill()
            stdout, stderr = process.communicate()
            return {
                'tool': 'nmap',
                'target': target,
                'command': cmd,
                'error': f'timeout after {timeout}s',
                'partial_stdout': stdout,
                'partial_stderr': stderr,
                'timestamp': datetime.now().isoformat(),
                'scan_type': scan_type
            }
    except Exception as e:
        logger.error(f"Erro no scan Nmap para {target}: {str(e)}")
        return {'tool': 'nmap', 'target': target, 'error': str(e), 'scan_type': scan_type}

def parse_nmap_results(nmap_output: str, logger_param: logging.Logger) -> Dict:
    """Parser melhorado para resultados do Nmap"""
    global logger
    logger = logger_param

    parsed = {
        'open_ports': [],
        'services': [],
        'os_info': '',
        'vulnerabilities': [],
        'host_status': 'unknown',
        'mac_address': '',
        'latency': '',
        'scripts_output': []
    }
    
    if not nmap_output:
        return parsed

    lines = nmap_output.split('\n')
    current_port = None
    
    for i, line in enumerate(lines):
        line = line.strip()
        
        # Status do host
        if 'Host is up' in line:
            parsed['host_status'] = 'up'
            # Extrai latência se disponível
            if 'latency' in line:
                latency_part = line.split('latency')[1].strip()
                if ')' in latency_part:
                    parsed['latency'] = latency_part.split(')')[0].strip('(')
        elif 'Host seems down' in line:
            parsed['host_status'] = 'down'
        
        # Portas abertas e serviços
        elif '/tcp' in line and 'open' in line:
            parts = line.split()
            if len(parts) >= 3:
                port_info = {
                    'port': parts[0],
                    'state': parts[1],
                    'service': parts[2],
                    'version': ' '.join(parts[3:]) if len(parts) > 3 else '',
                    'scripts': []
                }
                parsed['open_ports'].append(port_info)
                current_port = port_info
        
        # Informações do OS
        elif line.startswith('OS:') or line.startswith('Running:'):
            parsed['os_info'] += line + ' '
        elif 'OS details:' in line:
            parsed['os_info'] += line.replace('OS details:', '').strip() + ' '
        
        # MAC Address
        elif line.startswith('MAC Address:'):
            parsed['mac_address'] = line.replace('MAC Address:', '').strip()
        
        # Scripts NSE
        elif line.startswith('|') and current_port:
            script_line = line[1:].strip()
            current_port['scripts'].append(script_line)
            parsed['scripts_output'].append(f"Port {current_port['port']}: {script_line}")
            
            # Detecta vulnerabilidades em scripts
            if any(vuln_indicator in script_line.upper() for vuln_indicator in ['CVE-', 'OSVDB-', 'MSF:', 'VULNERABLE', 'EXPLOIT']):
                parsed['vulnerabilities'].append({
                    'port': current_port['port'],
                    'description': script_line,
                    'type': 'nse_script'
                })

    # Processa serviços únicos
    parsed['services'] = sorted(list(set([port['service'] for port in parsed['open_ports']])))
    
    # Limpa informações do OS
    if parsed['os_info']:
        parsed['os_info'] = parsed['os_info'].strip()
        
    return parsed

