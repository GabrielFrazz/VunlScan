import logging
import subprocess
import shutil
import shlex
from datetime import datetime
from typing import Dict, List

logger = logging.getLogger(__name__)


def run_testssl_scan(target: str, ssl_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa testssl.sh contra um target HTTPS.

    ssl_config keys:
      - enabled: bool
      - path: caminho para o script testssl.sh (default: 'testssl.sh')
      - timeout: tempo máximo em segundos
      - args: lista adicional de argumentos
    """
    log = logger_param

    if not ssl_config.get('enabled', False):
        log.info(f"testssl desabilitado para {target}")
        return {'tool': 'testssl', 'target': target, 'error': 'Ferramenta desabilitada'}

    script_path = ssl_config.get('path', 'testssl.sh')
    timeout = ssl_config.get('timeout', 300)
    extra_args = ssl_config.get('args', [])

    # Verifica se testssl está disponível
    if not shutil.which(script_path):
        log.error(f"testssl.sh não encontrado em '{script_path}'. Instale seguindo as instruções do README.")
        return {'tool': 'testssl', 'target': target, 'skipped': True, 'reason': f'testssl.sh não encontrado: {script_path}'}

    # Garante protocolo correto para testssl
    if target.startswith('http://'):
        test_target = target.replace('http://', 'https://')
    elif target.startswith('https://'):
        test_target = target
    else:
        test_target = f"https://{target}"

    # Usa lista de argumentos sem shell=True para evitar injeção
    cmd_list = [script_path, '--quiet'] + extra_args + [test_target]
    cmd_str = ' '.join(shlex.quote(p) for p in cmd_list)  # Apenas para logging

    log.info(f"Executando testssl.sh: {cmd_str}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_testssl_output(result.stdout, log)

        return {
            'tool': 'testssl',
            'target': target,
            'command': cmd_str,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        log.error(f"Timeout no testssl para {target} após {timeout}s")
        return {
            'tool': 'testssl',
            'target': target,
            'command': cmd_str,
            'error': f'timeout after {timeout}s',
            'elapsed_time': elapsed,
            'parsed': {}
        }
    except Exception as e:
        log.exception(f"Erro ao executar testssl.sh: {e}")
        return {'tool': 'testssl', 'target': target, 'error': str(e)}


def parse_testssl_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser simples para extrair problemas óbvios do testssl.sh

    Procura por linhas que indiquem problemas como: VULNERABLE, INSECURE, weak cipher, etc.
    """
    log = logger_param

    parsed = {
        'issues': [],
        'summary': {
            'vulnerable': 0,
            'warnings': 0,
            'ok': 0
        }
    }

    if not output:
        return parsed

    lines = output.split('\n')
    for line in lines:
        l = line.strip()
        if not l:
            continue

        up = l.upper()
        if ('VULNERABLE' in up and 'NOT VULNERABLE' not in up) or 'INSECURE' in up or 'WEAK' in up or 'BROKEN' in up:
            parsed['issues'].append({'type': 'vulnerable', 'message': l})
            parsed['summary']['vulnerable'] += 1
        elif 'WARNING' in up or 'DEPRECATED' in up:
            parsed['issues'].append({'type': 'warning', 'message': l})
            parsed['summary']['warnings'] += 1
        else:
            if 'ACCEPTED' in up or 'TLS' in up or 'HANDSHAKE' in up:
                parsed['summary']['ok'] += 1

    return parsed


def run_searchsploit_scan(target: str, search_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa buscas no searchsploit com base em um termo (ex: banner de serviço)

    search_config keys:
      - enabled: bool
      - path: caminho para o binário searchsploit (default: 'searchsploit')
      - timeout: segundos
      - query: termo de busca (se None, usa o target)
    """
    log = logger_param

    if not search_config.get('enabled', False):
        log.info(f"searchsploit desabilitado para {target}")
        return {'tool': 'searchsploit', 'target': target, 'error': 'Ferramenta desabilitada'}

    bin_path = search_config.get('path', 'searchsploit')
    timeout = search_config.get('timeout', 30)
    query = search_config.get('query') or target

    # Verifica se searchsploit está disponível
    if not shutil.which(bin_path):
        log.error(f"searchsploit não encontrado em '{bin_path}'. Instale com: sudo apt install exploitdb")
        return {'tool': 'searchsploit', 'target': target, 'skipped': True, 'reason': f'searchsploit não encontrado: {bin_path}'}

    # Lista de argumentos sem shell=True
    cmd_list = [bin_path, query]
    cmd_str = ' '.join(shlex.quote(p) for p in cmd_list)

    log.info(f"Executando searchsploit: {cmd_str}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_searchsploit_output(result.stdout, log)

        return {
            'tool': 'searchsploit',
            'target': target,
            'command': cmd_str,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        log.error(f"Timeout no searchsploit para {target} após {timeout}s")
        return {'tool': 'searchsploit', 'target': target, 'command': cmd_str, 'error': f'timeout after {timeout}s', 'elapsed_time': elapsed}
    except Exception as e:
        log.exception(f"Erro ao executar searchsploit: {e}")
        return {'tool': 'searchsploit', 'target': target, 'error': str(e)}


def parse_searchsploit_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser simples para saída do searchsploit"""
    log = logger_param

    parsed = {'results': [], 'count': 0}
    if not output:
        return parsed

    lines = output.split('\n')
    for line in lines:
        l = line.strip()
        if not l:
            continue
        # Ignora linhas de cabeçalho do próprio searchsploit
        if l.startswith('Type') or l.startswith('Codes') or l.startswith('--'):
            continue
        # Linhas com '|' são entradas de resultado
        if '|' in l:
            parts = [p.strip() for p in l.split('|') if p.strip()]
            if parts:
                parsed['results'].append({'raw': l, 'parts': parts})

    parsed['count'] = len(parsed['results'])
    return parsed


def run_enum4linux_scan(target: str, enum_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa enum4linux contra um target SMB/Windows

    enum_config keys:
      - enabled: bool
      - path: comando (default: 'enum4linux')
      - timeout: segundos
      - args: lista adicional
    """
    log = logger_param

    if not enum_config.get('enabled', False):
        log.info(f"enum4linux desabilitado para {target}")
        return {'tool': 'enum4linux', 'target': target, 'error': 'Ferramenta desabilitada'}

    bin_path = enum_config.get('path', 'enum4linux')
    timeout = enum_config.get('timeout', 120)
    extra_args = enum_config.get('args', ['-a'])

    # Verifica se enum4linux está disponível
    if not shutil.which(bin_path):
        log.error(f"enum4linux não encontrado em '{bin_path}'. Instale com: sudo apt install enum4linux")
        return {'tool': 'enum4linux', 'target': target, 'skipped': True, 'reason': f'enum4linux não encontrado: {bin_path}'}

    # Lista de argumentos sem shell=True
    cmd_list = [bin_path] + extra_args + [target]
    cmd_str = ' '.join(shlex.quote(p) for p in cmd_list)

    log.info(f"Executando enum4linux: {cmd_str}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_enum4linux_output(result.stdout, log)

        return {
            'tool': 'enum4linux',
            'target': target,
            'command': cmd_str,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        log.error(f"Timeout no enum4linux para {target} após {timeout}s")
        return {'tool': 'enum4linux', 'target': target, 'command': cmd_str, 'error': f'timeout after {timeout}s', 'elapsed_time': elapsed}
    except Exception as e:
        log.exception(f"Erro ao executar enum4linux: {e}")
        return {'tool': 'enum4linux', 'target': target, 'error': str(e)}


def parse_enum4linux_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser para enum4linux/enum4linux-ng

    Busca por itens importantes: shares, users, domain, OS, domain SID
    """
    log = logger_param

    parsed = {
        'shares': [],
        'users': [],
        'domains': [],
        'os': None,
        'raw': output
    }

    if not output:
        return parsed

    lines = output.split('\n')
    for line in lines:
        l = line.strip()
        if not l:
            continue
        up = l.upper()

        # Compartilhamentos — parênteses explícitos para evitar ambiguidade de precedência
        if 'Sharename' in l or ('Disk' in l and 'SHARE' in up):
            parsed['shares'].append(l)
        # Usuários — parênteses explícitos
        elif ('User:' in l) or ('RID:' in l and 'USER' in up):
            parsed['users'].append(l)
        # Domain / Workgroup
        elif 'Domain' in l or 'Workgroup' in l:
            parsed['domains'].append(l)
        # OS detection
        elif 'OS:' in l or 'Operating System' in l:
            if not parsed['os']:
                parsed['os'] = l

    return parsed


def run_snmp_scan(target: str, snmp_config: Dict, logger_param: logging.Logger) -> Dict:
    """Executa checks SNMP usando snmp-check e/ou snmpwalk

    snmp_config keys:
      - enabled: bool
      - community: comunidade para testar (default: 'public')
      - path_snmpcheck: caminho para snmp-check (default: 'snmp-check')
      - timeout: segundos
    """
    log = logger_param

    if not snmp_config.get('enabled', False):
        log.info(f"SNMP scanner desabilitado para {target}")
        return {'tool': 'snmp', 'target': target, 'error': 'Ferramenta desabilitada'}

    community = snmp_config.get('community', 'public')
    snmpcheck = snmp_config.get('path_snmpcheck', 'snmp-check')
    timeout = snmp_config.get('timeout', 60)

    # Verifica se snmp-check está disponível
    if not shutil.which(snmpcheck):
        log.warning(f"snmp-check não encontrado em '{snmpcheck}'. Tentando snmpwalk como alternativa.")
        snmpcheck = None

    if snmpcheck:
        # Lista de argumentos sem shell=True
        cmd_list = [snmpcheck, '-c', community, target]
        cmd_str = ' '.join(shlex.quote(p) for p in cmd_list)

        log.info(f"Executando snmp-check: {cmd_str}")
        start = datetime.now()
        try:
            result = subprocess.run(cmd_list, shell=False, capture_output=True, text=True, timeout=timeout)
            elapsed = (datetime.now() - start).total_seconds()
            parsed = parse_snmp_output(result.stdout, log)

            return {
                'tool': 'snmp',
                'target': target,
                'command': cmd_str,
                'returncode': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'elapsed_time': elapsed,
                'parsed': parsed
            }
        except subprocess.TimeoutExpired:
            elapsed = (datetime.now() - start).total_seconds()
            log.warning(f"Timeout no snmp-check para {target} após {timeout}s. Tentando snmpwalk...")
            # Cai no fallback abaixo
        except Exception as e:
            log.exception(f"Erro ao executar snmp-check: {e}")
            return {'tool': 'snmp', 'target': target, 'error': str(e)}

    # Fallback para snmpwalk
    if not shutil.which('snmpwalk'):
        log.error("snmpwalk também não encontrado. Instale snmp-mibs-downloader e snmp.")
        return {'tool': 'snmp', 'target': target, 'error': 'snmp-check e snmpwalk não encontrados no sistema'}

    try:
        cmd_list_walk = ['snmpwalk', '-v2c', '-c', community, target, '.1.3.6.1.2.1']
        cmd_str_walk = ' '.join(shlex.quote(p) for p in cmd_list_walk)
        start2 = datetime.now()
        result2 = subprocess.run(cmd_list_walk, shell=False, capture_output=True, text=True, timeout=timeout)
        elapsed2 = (datetime.now() - start2).total_seconds()
        parsed2 = parse_snmp_output(result2.stdout, log)
        return {
            'tool': 'snmp',
            'target': target,
            'command': cmd_str_walk,
            'returncode': result2.returncode,
            'stdout': result2.stdout,
            'stderr': result2.stderr,
            'elapsed_time': elapsed2,
            'parsed': parsed2
        }
    except Exception as e:
        log.exception(f"Erro no fallback snmpwalk: {e}")
        return {'tool': 'snmp', 'target': target, 'error': str(e)}


def parse_snmp_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser para saída de snmp-check/snmpwalk

    Busca por sysDescr, sysObjectID, contact, location e possíveis strings reveladoras.
    """
    log = logger_param

    parsed = {
        'sysdescr': None,
        'sysobjectid': None,
        'contact': None,
        'location': None,
        'community_default': False,
        'raw': output
    }

    if not output:
        return parsed

    lines = output.split('\n')
    for line in lines:
        l = line.strip()
        if not l:
            continue
        up = l.upper()

        if 'SYSDESCR' in up or 'SYS_DESCR' in up or 'sysDescr' in l:
            if not parsed['sysdescr']:
                parsed['sysdescr'] = l
        elif 'SYSOBJECTID' in up or 'sysObjectID' in l:
            if not parsed['sysobjectid']:
                parsed['sysobjectid'] = l
        elif 'CONTACT' in up or 'sysContact' in l:
            parsed['contact'] = l
        elif 'LOCATION' in up or 'sysLocation' in l:
            parsed['location'] = l

        # Detecta community string "public" de forma precisa:
        # só seta community_default quando a linha claramente indica autenticação com "public"
        # Evita false positives de linhas que contenham "public" em outro contexto
        if 'community_default' not in parsed or not parsed['community_default']:
            # Padrões específicos de snmp-check: "Community name: public" ou snmpwalk com "public" no início
            if ('COMMUNITY' in up and 'PUBLIC' in up) or l.lower().startswith('community name: public'):
                parsed['community_default'] = True

    return parsed
