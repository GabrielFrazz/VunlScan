import logging
import subprocess
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
    global logger
    logger = logger_param
    
    logger.info(f"Iniciando descoberta de hosts ativos na rede: {network}")
    
    # Valida se é CIDR ou IP
    if not (is_valid_cidr(network) or is_valid_ip(network)):
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': 'Formato de rede inválido. Use notação CIDR (ex: 192.168.1.0/24) ou IP único'
        }
    
    try:
        # Comando Nmap para descoberta de hosts (-sn = ping scan apenas)
        cmd = f"nmap -sn -T4 {network}"
        logger.info(f"Executando comando de descoberta: {cmd}")
        
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
        
        if result.returncode == 0:
            active_hosts = parse_nmap_discovery(result.stdout, logger_param)
            logger.info(f"Descoberta concluída em {elapsed_time:.2f}s. {len(active_hosts)} hosts ativos encontrados")
            
            return {
                'tool': 'nmap_discovery',
                'network': network,
                'command': cmd,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat(),
                'elapsed_time': elapsed_time,
                'active_hosts': active_hosts,
                'hosts_count': len(active_hosts)
            }
        else:
            logger.error(f"Erro na descoberta de hosts. Código de retorno: {result.returncode}")
            return {
                'tool': 'nmap_discovery',
                'network': network,
                'command': cmd,
                'error': f'Nmap retornou código {result.returncode}',
                'stderr': result.stderr,
                'timestamp': datetime.now().isoformat()
            }
            
    except subprocess.TimeoutExpired:
        logger.error(f"Timeout ({timeout}s) na descoberta de hosts para {network}")
        return {
            'tool': 'nmap_discovery',
            'network': network,
            'error': f'timeout after {timeout}s',
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        logger.error(f"Erro na descoberta de hosts para {network}: {str(e)}")
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
    global logger
    logger = logger_param
    
    active_hosts = []
    
    if not nmap_output:
        return active_hosts
    
    lines = nmap_output.split('\n')
    for line in lines:
        line = line.strip()
        
        # Procura por linhas que indicam hosts ativos
        # Formato típico: "Nmap scan report for 192.168.1.1"
        # Ou: "Nmap scan report for hostname (192.168.1.1)"
        if line.startswith('Nmap scan report for'):
            # Extrai o IP da linha
            if '(' in line and ')' in line:
                # Formato: "Nmap scan report for hostname (192.168.1.1)"
                ip = line.split('(')[1].split(')')[0]
            else:
                # Formato: "Nmap scan report for 192.168.1.1"
                ip = line.split('for ')[1]
            
            # Valida se é um IP válido antes de adicionar
            if is_valid_ip(ip):
                active_hosts.append(ip)
                logger.debug(f"Host ativo encontrado: {ip}")
    
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
    global logger
    logger = logger_param
    
    expanded_targets = []
    
    for target in targets:
        if is_valid_cidr(target) and '/' in target:
            # É uma rede CIDR, fazer descoberta
            logger.info(f"Expandindo rede CIDR: {target}")
            discovery_result = discover_active_hosts(target, logger_param)
            
            if 'active_hosts' in discovery_result:
                active_hosts = discovery_result['active_hosts']
                expanded_targets.extend(active_hosts)
                logger.info(f"Rede {target} expandida para {len(active_hosts)} hosts ativos")
            else:
                logger.warning(f"Falha na descoberta da rede {target}: {discovery_result.get('error', 'Erro desconhecido')}")
        else:
            # É um IP único ou domínio, manter como está
            expanded_targets.append(target)
    
    # Remove duplicatas e ordena
    unique_targets = sorted(list(set(expanded_targets)))
    logger.info(f"Total de targets após expansão: {len(unique_targets)}")
    
    return unique_targets

def test_host_connectivity(target: str, logger_param: logging.Logger, ports: List[int] = [80, 443, 22, 21, 25, 53]) -> Dict:
    """
    Testa conectividade com um host específico em portas comuns
    
    Args:
        target: IP ou hostname do target
        logger_param: Logger para registrar eventos
        ports: Lista de portas para testar (padrão: portas comuns)
    
    Returns:
        Dict com informações de conectividade
    """
    global logger
    logger = logger_param
    
    logger.debug(f"Testando conectividade com {target}")
    
    try:
        # Usa Nmap para teste rápido de conectividade
        ports_str = ','.join(map(str, ports))
        cmd = f"nmap -Pn -T4 --top-ports 10 {target}"
        
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            errors='ignore',
            timeout=30  # Timeout curto para teste de conectividade
        )
        
        if result.returncode == 0:
            # Parse básico para verificar se há portas abertas
            open_ports = []
            for line in result.stdout.split('\n'):
                if '/tcp' in line and 'open' in line:
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

