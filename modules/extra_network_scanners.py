import logging
import subprocess
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
    global logger
    logger = logger_param

    if not ssl_config.get('enabled', False):
        logger.info(f"testssl desabilitado para {target}")
        return {'tool': 'testssl', 'target': target, 'error': 'Ferramenta desabilitada'}

    script_path = ssl_config.get('path', 'testssl.sh')
    timeout = ssl_config.get('timeout', 300)
    extra_args = ssl_config.get('args', [])

    # Garante que target comece com protocolo (testssl aceita host:port ou https://host)
    if target.startswith('http://'):
        test_target = target.replace('http://', 'https://')
    elif target.startswith('https://'):
        test_target = target
    else:
        # Assume HTTPS por padrão para scanner SSL
        test_target = f"https://{target}"

    cmd_parts = [script_path, '--quiet'] + extra_args + [test_target]
    cmd = ' '.join(shlex.quote(p) for p in cmd_parts)

    logger.info(f"Executando testssl.sh: {cmd}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_testssl_output(result.stdout, logger_param)

        return {
            'tool': 'testssl',
            'target': target,
            'command': cmd,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        logger.error(f"Timeout no testssl para {target} após {timeout}s")
        return {
            'tool': 'testssl',
            'target': target,
            'command': cmd,
            'error': f'timeout after {timeout}s',
            'elapsed_time': elapsed,
            'parsed': {}
        }
    except Exception as e:
        logger.exception(f"Erro ao executar testssl.sh: {e}")
        return {'tool': 'testssl', 'target': target, 'error': str(e)}


def parse_testssl_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser simples para extrair problemas óbvios do testssl.sh

    Procura por linhas que indiquem problemas como: VULNERABLE, INSECURE, weak cipher, etc.
    """
    global logger
    logger = logger_param

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
        if 'VULNERABLE' in up or 'INSECURE' in up or 'WEAK' in up or 'BROKEN' in up:
            parsed['issues'].append({'type': 'vulnerable', 'message': l})
            parsed['summary']['vulnerable'] += 1
        elif 'WARNING' in up or 'DEPRECATED' in up:
            parsed['issues'].append({'type': 'warning', 'message': l})
            parsed['summary']['warnings'] += 1
        else:
            # pequenas heurísticas para contar "ok"
            if 'accepted' in up or 'TLS' in up or 'HANDSHAKE' in up:
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
    global logger
    logger = logger_param

    if not search_config.get('enabled', False):
        logger.info(f"searchsploit desabilitado para {target}")
        return {'tool': 'searchsploit', 'target': target, 'error': 'Ferramenta desabilitada'}

    bin_path = search_config.get('path', 'searchsploit')
    timeout = search_config.get('timeout', 30)
    query = search_config.get('query') or target

    # Monta comando simples: searchsploit '<query>'
    # Note que searchsploit aceita buscas por termos; se desejar JSON, verifique a versão instalada.
    cmd = f"{shlex.quote(bin_path)} {shlex.quote(query)}"

    logger.info(f"Executando searchsploit: {cmd}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_searchsploit_output(result.stdout, logger_param)

        return {
            'tool': 'searchsploit',
            'target': target,
            'command': cmd,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        logger.error(f"Timeout no searchsploit para {target} após {timeout}s")
        return {'tool': 'searchsploit', 'target': target, 'command': cmd, 'error': f'timeout after {timeout}s', 'elapsed_time': elapsed}
    except Exception as e:
        logger.exception(f"Erro ao executar searchsploit: {e}")
        return {'tool': 'searchsploit', 'target': target, 'error': str(e)}


def parse_searchsploit_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser simples para saída do searchsploit

    A saída padrão lista resultados com o seguinte formato aproximado:
      Exploit Title                | Path/EDB-ID | ...

    Este parser extrai linhas não vazias e retorna como possíveis exploits.
    """
    global logger
    logger = logger_param

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
        # Simples heurística: linhas contendo '|' são entradas
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
    global logger
    logger = logger_param

    if not enum_config.get('enabled', False):
        logger.info(f"enum4linux desabilitado para {target}")
        return {'tool': 'enum4linux', 'target': target, 'error': 'Ferramenta desabilitada'}

    bin_path = enum_config.get('path', 'enum4linux')
    timeout = enum_config.get('timeout', 120)
    extra_args = enum_config.get('args', ['-a'])

    cmd_parts = [bin_path] + extra_args + [target]
    cmd = ' '.join(shlex.quote(p) for p in cmd_parts)

    logger.info(f"Executando enum4linux: {cmd}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_enum4linux_output(result.stdout, logger_param)

        return {
            'tool': 'enum4linux',
            'target': target,
            'command': cmd,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        logger.error(f"Timeout no enum4linux para {target} após {timeout}s")
        return {'tool': 'enum4linux', 'target': target, 'command': cmd, 'error': f'timeout after {timeout}s', 'elapsed_time': elapsed}
    except Exception as e:
        logger.exception(f"Erro ao executar enum4linux: {e}")
        return {'tool': 'enum4linux', 'target': target, 'error': str(e)}


def parse_enum4linux_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser para enum4linux/enum4linux-ng

    Busca por itens importantes: shares, users, domain, OS, domain SID
    """
    global logger
    logger = logger_param

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

        # Compartilhamentos
        if 'Sharename' in l or 'Disk' in l and 'SHARE' in up:
            parsed['shares'].append(l)
        # Usuários (heurística)
        elif 'User:' in l or 'RID:' in l and 'USER' in up:
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
    global logger
    logger = logger_param

    if not snmp_config.get('enabled', False):
        logger.info(f"SNMP scanner desabilitado para {target}")
        return {'tool': 'snmp', 'target': target, 'error': 'Ferramenta desabilitada'}

    community = snmp_config.get('community', 'public')
    snmpcheck = snmp_config.get('path_snmpcheck', 'snmp-check')
    timeout = snmp_config.get('timeout', 60)

    # Primeiro tenta snmp-check (mais amigável)
    cmd_check = f"{shlex.quote(snmpcheck)} -c {shlex.quote(community)} {shlex.quote(target)}"

    logger.info(f"Executando snmp-check: {cmd_check}")
    start = datetime.now()
    try:
        result = subprocess.run(cmd_check, shell=True, capture_output=True, text=True, timeout=timeout)
        elapsed = (datetime.now() - start).total_seconds()

        parsed = parse_snmp_output(result.stdout, logger_param)

        return {
            'tool': 'snmp',
            'target': target,
            'command': cmd_check,
            'returncode': result.returncode,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'elapsed_time': elapsed,
            'parsed': parsed
        }
    except subprocess.TimeoutExpired:
        elapsed = (datetime.now() - start).total_seconds()
        logger.warning(f"Timeout no snmp-check para {target} após {timeout}s. Tentando snmpwalk...")
        # fallback para snmpwalk
        try:
            cmd_walk = f"snmpwalk -v2c -c {shlex.quote(community)} {shlex.quote(target)} .1.3.6.1.2.1"
            start2 = datetime.now()
            result2 = subprocess.run(cmd_walk, shell=True, capture_output=True, text=True, timeout=timeout)
            elapsed2 = (datetime.now() - start2).total_seconds()
            parsed2 = parse_snmp_output(result2.stdout, logger_param)
            return {
                'tool': 'snmp',
                'target': target,
                'command': cmd_walk,
                'returncode': result2.returncode,
                'stdout': result2.stdout,
                'stderr': result2.stderr,
                'elapsed_time': elapsed2,
                'parsed': parsed2
            }
        except Exception as e:
            logger.exception(f"Erro no fallback snmpwalk: {e}")
            return {'tool': 'snmp', 'target': target, 'error': str(e)}
    except Exception as e:
        logger.exception(f"Erro ao executar snmp-check: {e}")
        return {'tool': 'snmp', 'target': target, 'error': str(e)}


def parse_snmp_output(output: str, logger_param: logging.Logger) -> Dict:
    """Parser para saída de snmp-check/snmpwalk

    Busca por sysDescr, sysObjectID, contact, location e possíveis strings reveladoras.
    """
    global logger
    logger = logger_param

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
        # Verifica se a comunidade public foi retornada como parte do output
        if 'public' in l.lower():
            parsed['community_default'] = True

    return parsed
