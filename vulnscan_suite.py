import argparse
import json
import logging
import os
import sys
import signal
import threading
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List, Any
from datetime import datetime

# Importações dos módulos locais
from modules import nmap_scanner, nikto_scanner, dirb_scanner, report_generator, network_discovery, extra_network_scanners

# Variável global para logger, configurada por setup_logging
logger: logging.Logger

def setup_logging():
    """Configura o sistema de logging"""
    global logger
    os.makedirs('logs', exist_ok=True)
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler('logs/vulnscan.log', mode='a', encoding='utf-8'),
            logging.StreamHandler(sys.stdout)
        ]
    )
    logger = logging.getLogger("VulnScanSuite")
    # Configura loggers dos módulos
    for module_name in ['modules.nmap_scanner', 'modules.nikto_scanner', 'modules.dirb_scanner', 
                       'modules.report_generator', 'modules.network_discovery', 
                       'modules.web_service_detector', 'modules.extra_network_scanners']:
        logging.getLogger(module_name).setLevel(logging.INFO)
    return logger

class VulnScanSuite:
    """Classe principal do VulnScan Suite melhorado"""
    
    def __init__(self, config_file="config/tools_config.json"):
        global logger
        self.logger = logger 
        self.config_file = config_file
        self.config = self.load_config()
        self.results = {
            'scan_info': {
                'start_time': datetime.now().isoformat(),
                'tools_used': [],
                'targets': [],
                'scan_intensity': 'basic',
                'network_discovery': False,
                'original_targets': [],
                'expanded_targets': []
            },
            'discovery_results': {},
            'results': {}
        }
        self.interrupted = False
        
    def signal_handler(self, signum, frame):
        """Handler para interrupção do usuário"""
        self.logger.warning("Interrupção detectada (Ctrl+C). Finalizando scans e processos ativos...")
        self.interrupted = True

    def load_config(self) -> Dict:
        """Carrega configurações das ferramentas"""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                self.logger.info(f"Configuração carregada de: {self.config_file}")
                return config
            else:
                self.logger.warning(f"Arquivo de configuração {self.config_file} não encontrado. Usando configuração padrão.")
                return self.get_default_config()
        except Exception as e:
            self.logger.error(f"Erro ao carregar configuração: {str(e)}. Usando configuração padrão.")
            return self.get_default_config()
    
    def get_default_config(self) -> Dict:
        """Configuração padrão das ferramentas"""
        return {
            "nmap": {
                "enabled": True,
                "default_flags": ["-sV", "-sC"],
                "timing": "-T4",
                "max_ports": "1000",
                "timeout": 900,
                "timeout_quick": 300,
                "timeout_basic": 600,
                "timeout_comprehensive": 900,
                "timeout_vuln": 1800,
                "timeout_discovery": 300,
                "custom_scripts": []
            },
            "nikto": {
                "enabled": True,
                "max_time": 600,
                "custom_flags": ["-Tuning", "1,2,3,4,5,b"]
            },
            "dirb": {
                "enabled": True,
                "wordlist": "/usr/share/dirb/wordlists/common.txt",
                "timeout": 600,
                "extensions": [".php", ".html", ".txt", ".js"]
            },
            "network_discovery": {
                "enabled": True,
                "timeout": 300,
                "auto_expand_cidr": True
            },
            "testssl": {
                "enabled": False,
                "path": "testssl.sh",
                "timeout": 300,
                "args": ["-U"]
            },
            "searchsploit": {
                "enabled": False,
                "path": "searchsploit",
                "timeout": 60,
                "query": None
            },
            "enum4linux": {
                "enabled": False,
                "path": "enum4linux",
                "timeout": 120,
                "args": ["-a"]
            },
            "snmp": {
                "enabled": False,
                "path_snmpcheck": "snmp-check",
                "timeout": 60,
                "community": "public"
            }
        }
        
    def save_default_config(self):
        """Salva configuração padrão se não existir"""
        if not os.path.exists(self.config_file):
            os.makedirs(os.path.dirname(self.config_file), exist_ok=True)
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(self.get_default_config(), f, indent=2, ensure_ascii=False)
            self.logger.info(f"Configuração padrão salva em: {self.config_file}")

    def expand_targets(self, targets: List[str], enable_discovery: bool = True) -> List[str]:
        """Expande targets CIDR para hosts ativos"""
        if not enable_discovery:
            return targets
            
        self.logger.info("🔍 Iniciando descoberta e expansão de targets...")
        self.results['scan_info']['original_targets'] = targets.copy()
        
        expanded = network_discovery.expand_network_targets(targets, self.logger)
        
        self.results['scan_info']['expanded_targets'] = expanded
        self.results['scan_info']['network_discovery'] = True
        
        if len(expanded) != len(targets):
            self.logger.info(f"Targets expandidos: {len(targets)} → {len(expanded)}")
        
        return expanded

    def test_connectivity(self, targets: List[str]) -> List[str]:
        """Testa conectividade com targets e retorna apenas os acessíveis"""
        self.logger.info("🔍 Testando conectividade com targets...")
        accessible_targets = []
        
        for i, target in enumerate(targets, 1):
            if self.interrupted:
                break
                
            self.logger.info(f"Testando {i}/{len(targets)}: {target}")
            connectivity_result = network_discovery.test_host_connectivity(target, self.logger)
            
            if connectivity_result.get('accessible', False):
                accessible_targets.append(target)
                open_ports = connectivity_result.get('open_ports', [])
                self.logger.info(f"  ✅ {target} acessível (portas abertas: {', '.join(open_ports) if open_ports else 'nenhuma detectada'})")
            else:
                error = connectivity_result.get('error', 'não acessível')
                self.logger.warning(f"  ❌ {target} não acessível ({error})")
        
        self.logger.info(f"Conectividade: {len(accessible_targets)}/{len(targets)} targets acessíveis")
        return accessible_targets

    def scan_target(self, target: str, tools_to_run: List[str], scan_intensity: str) -> Dict:
        """Executa scans em um target usando os módulos apropriados"""
        target_results = {}
        if self.interrupted:
            return {'error': 'Scan interrompido pelo usuário antes de iniciar para este target.'}

        self.logger.info(f"Iniciando scan do target '{target}' com intensidade '{scan_intensity}' e ferramentas: {', '.join(tools_to_run)}")

        max_workers = 1 if len(tools_to_run) == 1 else min(len(tools_to_run), 5)
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            
            # Scanners padrão
            if 'nmap' in tools_to_run and self.config.get('nmap', {}).get('enabled', False):
                nmap_config_tool = self.config.get('nmap', {})
                nmap_scan_type_map = {
                    'quick': 'quick', 'basic': 'basic', 'normal': 'comprehensive', 'comprehensive': 'vuln'
                }
                nmap_scan_type = nmap_scan_type_map.get(scan_intensity, 'basic')
                futures['nmap'] = executor.submit(nmap_scanner.run_nmap_scan, target, nmap_config_tool, self.logger, scan_type=nmap_scan_type)

            if 'nikto' in tools_to_run and self.config.get('nikto', {}).get('enabled', False):
                nikto_config_tool = self.config.get('nikto', {})
                futures['nikto'] = executor.submit(nikto_scanner.run_nikto_scan, target, nikto_config_tool, self.logger)
            
            if 'dirb' in tools_to_run and self.config.get('dirb', {}).get('enabled', False):
                dirb_config_tool = self.config.get('dirb', {})
                futures['dirb'] = executor.submit(dirb_scanner.run_dirb_scan, target, dirb_config_tool, self.logger)

            # Scanners extras
            if 'testssl' in tools_to_run and self.config.get('testssl', {}).get('enabled', False):
                testssl_config = self.config.get('testssl', {})
                futures['testssl'] = executor.submit(extra_network_scanners.run_testssl_scan, target, testssl_config, self.logger)

            if 'searchsploit' in tools_to_run and self.config.get('searchsploit', {}).get('enabled', False):
                searchsploit_config = self.config.get('searchsploit', {})
                # Para uma busca mais eficaz, poderíamos usar banners de serviços do Nmap.
                # Por simplicidade, usamos o target como termo de busca.
                futures['searchsploit'] = executor.submit(extra_network_scanners.run_searchsploit_scan, target, searchsploit_config, self.logger)

            if 'enum4linux' in tools_to_run and self.config.get('enum4linux', {}).get('enabled', False):
                enum4linux_config = self.config.get('enum4linux', {})
                futures['enum4linux'] = executor.submit(extra_network_scanners.run_enum4linux_scan, target, enum4linux_config, self.logger)
            
            if 'snmp' in tools_to_run and self.config.get('snmp', {}).get('enabled', False):
                snmp_config = self.config.get('snmp', {})
                futures['snmp'] = executor.submit(extra_network_scanners.run_snmp_scan, target, snmp_config, self.logger)

            # Coleta resultados
            for tool_name, future in futures.items():
                if self.interrupted:
                    self.logger.info(f"Cancelando task futura para {tool_name} em {target} devido à interrupção.")
                    future.cancel()
                    target_results[tool_name] = {'error': 'Scan interrompido pelo usuário.', 'status': 'cancelled'}
                    continue
                
                try:
                    timeout_map_future = {
                        'quick': 700, 'basic': 1000, 'normal': 1300, 'comprehensive': 2000 
                    }
                    future_timeout = timeout_map_future.get(scan_intensity, 1000)
                    result = future.result(timeout=future_timeout) 
                    target_results[tool_name] = result
                    
                    if tool_name == 'nmap' and not result.get('error') and not result.get('skipped'):
                        output_key = 'stdout' if 'stdout' in result else 'partial_stdout'
                        if output_key in result:
                             result['parsed'] = nmap_scanner.parse_nmap_results(result[output_key], self.logger)
                        else:
                             result['parsed'] = nmap_scanner.parse_nmap_results("", self.logger)

                except TimeoutError:
                     self.logger.error(f"Timeout geral ao aguardar resultado de {tool_name} em {target}.")
                     target_results[tool_name] = {'error': f'Timeout geral da thread pool para {tool_name}', 'status': 'timeout_pool'}
                except Exception as e:
                    self.logger.error(f"Erro ao coletar resultado de {tool_name} em {target}: {str(e)}")
                    target_results[tool_name] = {'error': str(e), 'status': 'error_collecting'}
        
        return target_results

    def run_scan_suite(self, targets: List[str], tools_to_run: List[str], scan_intensity: str, 
                      enable_discovery: bool = True, test_connection: bool = False):
        """Executa suite completa de scans com descoberta de rede"""
        original_sigint_handler = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self.signal_handler)

        self.logger.info(f"Iniciando VulnScan Suite para {len(targets)} target(s) com intensidade '{scan_intensity}'")
        
        if enable_discovery:
            expanded_targets = self.expand_targets(targets, enable_discovery)
        else:
            expanded_targets = targets
        
        if test_connection and not self.interrupted:
            accessible_targets = self.test_connectivity(expanded_targets)
        else:
            accessible_targets = expanded_targets
        
        if not accessible_targets:
            self.logger.warning("Nenhum target acessível encontrado. Encerrando.")
            signal.signal(signal.SIGINT, original_sigint_handler)
            return self.results
        
        self.results['scan_info']['targets'] = accessible_targets
        self.results['scan_info']['tools_used'] = tools_to_run
        self.results['scan_info']['scan_intensity'] = scan_intensity
        
        estimated_time = report_generator.estimate_scan_time(len(accessible_targets), tools_to_run, scan_intensity, self.logger)
        self.logger.info(f"⏱️  Tempo estimado de execução: {estimated_time}")
        
        for i, target in enumerate(accessible_targets, 1):
            if self.interrupted:
                self.logger.info("Scan interrompido pelo usuário. Parando processamento de novos targets.")
                break
            
            self.logger.info(f"--- Processando target {i}/{len(accessible_targets)}: {target} ---")
            target_scan_results = self.scan_target(target, tools_to_run, scan_intensity)
            self.results['results'][target] = target_scan_results
        
        self.results['scan_info']['end_time'] = datetime.now().isoformat()
        
        if self.results['results']:
            self.logger.info("💾 Salvando relatórios...")
            report_generator.save_results(self.results, 'json', self.logger)
            report_generator.save_results(self.results, 'txt', self.logger)
            report_generator.save_results(self.results, 'html', self.logger)
            self.logger.info("Scan suite finalizado.")
            if self.interrupted:
                 self.logger.warning("A suite foi interrompida. Alguns resultados podem estar incompletos ou ausentes.")
        else:
            self.logger.warning("Nenhum resultado para salvar (possivelmente devido a interrupção precoce ou nenhum target processado).")

        signal.signal(signal.SIGINT, original_sigint_handler)
        return self.results

def main():
    global logger
    logger = setup_logging()

    parser = argparse.ArgumentParser(description='VulnScan Suite - Análise Integrada de Vulnerabilidades (Versão Melhorada)')
    parser.add_argument('-t', '--target', help='Target IP, domínio ou rede CIDR (pode ser usado múltiplas vezes)', action='append', default=[])
    parser.add_argument('-f', '--file', help='Arquivo com lista de targets (um por linha)')
    parser.add_argument('--tools', nargs='+', default=['nmap', 'nikto', 'dirb'], 
                        choices=['nmap', 'nikto', 'dirb', 'testssl', 'searchsploit', 'enum4linux', 'snmp'], 
                        help='Ferramentas a serem utilizadas')
    parser.add_argument('--config', default='config/tools_config.json', 
                        help='Arquivo de configuração das ferramentas')
    parser.add_argument('--quick', action='store_true', 
                        help='Scan rápido (equivale a --intensity quick --tools nmap)')
    parser.add_argument('--intensity', choices=['quick', 'basic', 'normal', 'comprehensive'], 
                        default='basic', help='Intensidade do scan')
    parser.add_argument('--create-config', action='store_true',
                        help='Cria arquivo de configuração padrão e sai')
    parser.add_argument('--test-connection', action='store_true',
                        help='Testa conectividade com os targets antes do scan')
    parser.add_argument('--no-discovery', action='store_true',
                        help='Desabilita descoberta automática de hosts em redes CIDR')
    
    args = parser.parse_args()
    
    suite = VulnScanSuite(args.config)
    
    if args.create_config:
        suite.save_default_config()
        print(f"Arquivo de configuração padrão criado em: {os.path.join(os.getcwd(), args.config)}")
        return
        
    targets_list = list(args.target)
    
    if args.file:
        try:
            if os.path.exists(args.file):
                with open(args.file, 'r', encoding='utf-8') as f:
                    file_targets = [line.strip() for line in f if line.strip() and not line.startswith('#')]
                targets_list.extend(file_targets)
                logger.info(f"Carregados {len(file_targets)} targets do arquivo: {args.file}")
            else:
                logger.error(f"Arquivo de targets não encontrado: {args.file}")
                return
        except Exception as e:
            logger.error(f"Erro ao ler arquivo de targets '{args.file}': {str(e)}")
            return
            
    if not targets_list:
        parser.error("Nenhum target especificado. Use -t, --target ou -f, --file.")
        return
        
    unique_targets = sorted(list(dict.fromkeys(targets_list)))
    
    tools_to_use = args.tools
    scan_intensity_level = args.intensity

    if args.quick:
        scan_intensity_level = 'quick'
        tools_to_use = ['nmap']
        logger.info("Modo de scan rápido ativado: Intensidade 'quick', Ferramenta 'nmap'.")

    # Executa a suite
    suite.run_scan_suite(
        targets=unique_targets,
        tools_to_run=tools_to_use,
        scan_intensity=scan_intensity_level,
        enable_discovery=not args.no_discovery,
        test_connection=args.test_connection
    )

if __name__ == "__main__":
    main()