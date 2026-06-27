import logging
import subprocess
import shutil
import ipaddress
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

def is_valid_cidr(target: str) -> bool:
    """Verifica se o target é uma notação CIDR válida"""
    try:
        ipaddress.ip_network(target, strict=False)
        return True
    except ValueError:
        return False

def is_valid_ip(target: str) -> bool:
    """Verifica se o target é um IP válido"""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False

def discover_active_hosts(network: str, logger_param: logging.Logger, timeout: int = 300) -> Dict:
    """
    Descobre hosts ativos em uma rede usando Nmap ping scan
    
    Args:
        network: Rede em notação CIDR (ex: 192.168.1.0/24) ou IP único
        logger_param: Logger para registrar eventos
        timeout: Timeout em segundos para o scan
    
    Returns:
        Dict com informações dos hosts descobertos
    """
    log = logger_param
    
    log.info(f"Iniciando descoberta de hosts ativos na rede: {network}")
    
    # Valida se é CIDR ou IP
    if not (is_valid_cidr(network) or is_valid_ip(network)):
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': 'Formato de rede inválido. Use notação CIDR (ex: 192.168.1.0/24) ou IP único'
        }
    
    if not shutil.which('nmap'):
        log.error("nmap não encontrado no PATH. Instale com: sudo apt install nmap")
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': 'nmap não encontrado no sistema'
        }

    try:
        # Sem shell=True — lista de argumentos para evitar injeção de comandos
        cmd_list = ['nmap', '-sn', '-T4', network]
        cmd_str = ' '.join(cmd_list)
        log.info(f"Executando comando de descoberta: {cmd_str}")
        
        start_time = datetime.now()
        result = subprocess.run(
            cmd_list,
            shell=False,
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=timeout
        )
        elapsed_time = (datetime.now() - start_time).total_seconds()
        
        if result.returncode == 0:
            active_hosts = parse_nmap_discovery(result.stdout, log)
            log.info(f"Descoberta concluída em {elapsed_time:.2f}s. {len(active_hosts)} hosts ativos encontrados")
            
            return {
                'tool': 'nmap_discovery',
                'network': network,
                'command': cmd_str,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time': elapsed_time,
                'active_hosts': active_hosts,
                'hosts_count': len(active_hosts)
            }
        else:
            log.error(f"Erro na descoberta de hosts. Código de retorno: {result.returncode}")
            return {
                'tool': 'nmap_discovery',
                'network': network,
                'command': cmd_str,
                'error': f'Nmap retornou código {result.returncode}',
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
    except subprocess.TimeoutExpired:
        log.error(f"Timeout ({timeout}s) na descoberta de hosts para {network}")
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': f'timeout after {timeout}s',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        log.error(f"Erro na descoberta de hosts para {network}: {str(e)}")
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }

def parse_nmap_discovery(nmap_output: str, logger_param: logging.Logger) -> List[str]:
    """
    Faz o parse da saída do Nmap discovery para extrair IPs dos hosts ativos
    
    Args:
        nmap_output: Saída do comando nmap -sn
        logger_param: Logger para registrar eventos
    
    Returns:
        Lista de IPs dos hosts ativos
    """
    log = logger_param
    active_hosts = []
    
    if not nmap_output:
        return active_hosts
    
    lines = nmap_output.split('\n')
    for line in lines:
        line = line.strip()
        
        # Formato típico: "Nmap scan report for 192.168.1.1"
        # Ou: "Nmap scan report for hostname (192.168.1.1)"
        if line.startswith('Nmap scan report for'):
            try:
                if '(' in line and ')' in line:
                    # Formato com hostname: extrai IP entre parênteses
                    ip = line.split('(')[1].split(')')[0].strip()
                else:
                    # Formato direto: IP após "for "
                    ip = line.split('for ')[1].strip()
                
                if is_valid_ip(ip):
                    active_hosts.append(ip)
                    log.debug(f"Host ativo encontrado: {ip}")
            except (IndexError, ValueError):
                log.debug(f"Linha de descoberta não pôde ser parseada: {line}")
    
    return active_hosts

def expand_network_targets(targets: List[str], logger_param: logging.Logger) -> List[str]:
    """
    Expande targets que são redes CIDR para lista de hosts ativos
    
    Args:
        targets: Lista de targets (pode conter IPs, domínios ou redes CIDR)
        logger_param: Logger para registrar eventos
    
    Returns:
        Lista expandida de targets (apenas IPs e domínios)
    """
    log = logger_param
    expanded_targets = []
    
    for target in targets:
        if is_valid_cidr(target) and '/' in target:
            log.info(f"Expandindo rede CIDR: {target}")
            discovery_result = discover_active_hosts(target, log)
            
            if 'active_hosts' in discovery_result:
                active_hosts = discovery_result['active_hosts']
                expanded_targets.extend(active_hosts)
                log.info(f"Rede {target} expandida para {len(active_hosts)} hosts ativos")
            else:
                log.warning(f"Falha na descoberta da rede {target}: {discovery_result.get('error', 'Erro desconhecido')}")
        else:
            expanded_targets.append(target)
    
    # Remove duplicatas e ordena
    unique_targets = sorted(list(set(expanded_targets)))
    log.info(f"Total de targets após expansão: {len(unique_targets)}")
    
    return unique_targets

def test_host_connectivity(target: str, logger_param: logging.Logger, ports: Optional[List[int]] = None) -> Dict:
    """
    Testa conectividade com um host específico em portas comuns
    
    Args:
        target: IP ou hostname do target
        logger_param: Logger para registrar eventos
        ports: Lista de portas para testar (padrão: portas comuns). None usa o padrão.
    
    Returns:
        Dict com informações de conectividade
    """
    log = logger_param

    # Argumento default não mutable — cria nova lista se None
    if ports is None:
        ports = [80, 443, 22, 21, 25, 53]

    log.debug(f"Testando conectividade com {target}")
    
    if not shutil.which('nmap'):
        log.warning("nmap não encontrado — teste de conectividade via socket não disponível")
        return {
            'target': target,
            'accessible': False,
            'error': 'nmap não encontrado',
            'method': 'nmap_connectivity_test'
        }

    try:
        # Usa as portas fornecidas como parâmetro (corrigido — antes usava --top-ports 10 ignorando o parâmetro)
        ports_str = ','.join(map(str, ports))
        cmd_list = ['nmap', '-Pn', '-T4', '-p', ports_str, target]
        cmd_str = ' '.join(cmd_list)
        
        result = subprocess.run(
            cmd_list,
            shell=False,
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=30
        )
        
        if result.returncode == 0:
            open_ports = []
            for line in result.stdout.split('\n'):
                if ('/tcp' in line or '/udp' in line) and 'open' in line:
                    port = line.split('/')[0].strip()
                    open_ports.append(port)
            
            is_accessible = len(open_ports) > 0
            
            return {
                'target': target,
                'accessible': is_accessible,
                'open_ports': open_ports,
                'method': 'nmap_connectivity_test'
            }
        else:
            return {
                'target': target,
                'accessible': False,
                'error': f'Nmap retornou código {result.returncode}',
                'method': 'nmap_connectivity_test'
            }
            
    except subprocess.TimeoutExpired:
        return {
            'target': target,
            'accessible': False,
            'error': 'timeout',
            'method': 'nmap_connectivity_test'
        }
    except Exception as e:
        return {
            'target': target,
            'accessible': False,
            'error': str(e),
            'method': 'nmap_connectivity_test'
        }
