import json
import logging
import os
from datetime import datetime
from typing import Dict, List
import base64

logger = logging.getLogger(__name__)

def generate_summary_report(results: Dict, logger_param: logging.Logger) -> str:
    global logger
    logger = logger_param
    
    summary = []
    scan_info = results.get('scan_info', {})

    stats = calculate_statistics(results)
    
    summary.append("=" * 60)
    summary.append("VULNSCAN SUITE - RELATÓRIO RESUMIDO")
    summary.append("=" * 60)
    summary.append(f"Data do scan: {scan_info.get('start_time', 'N/A')}")
    summary.append(f"Ferramentas utilizadas: {', '.join(scan_info.get('tools_used', []))}")
    summary.append(f"Intensidade do scan: {scan_info.get('scan_intensity', 'N/A')}")
    summary.append(f"Targets originais: {len(scan_info.get('original_targets', []))}")
    summary.append(f"Targets analisados: {len(scan_info.get('targets', []))}")
    
    if scan_info.get('network_discovery', False):
        summary.append("🔍 Descoberta de rede: HABILITADA")
    
    summary.append("")

    # Estatísticas gerais
    total_ports = 0
    total_vulnerabilities = 0
    total_web_findings = 0
    hosts_up = 0
    hosts_with_web = 0
    
    for target, target_results_tools in results.get('results', {}).items():
        summary.append(f"\n{'='*50}")
        summary.append(f"TARGET: {target}")
        summary.append(f"{'='*50}")
        
        target_has_web = False
        
        # Resumo Nmap
        if 'nmap' in target_results_tools:
            nmap_data = target_results_tools['nmap']
            if 'error' in nmap_data:
                summary.append(f"❌ Nmap: {nmap_data['error']}")
            elif 'parsed' in nmap_data:
                parsed = nmap_data['parsed']
                host_status = parsed.get('host_status', 'unknown')
                
                if host_status == 'up':
                    hosts_up += 1
                
                summary.append(f"🖥️  Status do host: {host_status.upper()}")
                
                open_ports = parsed.get('open_ports', [])
                total_ports += len(open_ports)
                
                if open_ports:
                    summary.append(f"🔌 Portas abertas ({len(open_ports)}):")
                    for i, port in enumerate(open_ports[:10]):  # Primeiras 10 portas
                        port_num = port.get('port', 'N/A')
                        service = port.get('service', 'N/A')
                        version = port.get('version', '')
                        summary.append(f"   {i+1:2d}. {port_num:15s} {service:15s} {version}")
                    
                    if len(open_ports) > 10:
                        summary.append(f"   ... e mais {len(open_ports) - 10} portas.")
                
                services = parsed.get('services', [])
                if services:
                    summary.append(f"🔧 Serviços: {', '.join(services[:8])}")
                    if len(services) > 8:
                        summary.append(f"   ... e mais {len(services) - 8} serviços.")
                
                if parsed.get('os_info'):
                    summary.append(f"💻 OS Info: {parsed['os_info']}")
                
                if parsed.get('mac_address'):
                    summary.append(f"🏷️  MAC: {parsed['mac_address']}")
                
                vulnerabilities = parsed.get('vulnerabilities', [])
                if vulnerabilities:
                    total_vulnerabilities += len(vulnerabilities)
                    summary.append(f"⚠️  Vulnerabilidades Nmap ({len(vulnerabilities)}):")
                    for vuln in vulnerabilities[:3]:
                        summary.append(f"   - {vuln.get('description', 'N/A')}")
                    if len(vulnerabilities) > 3:
                        summary.append(f"   ... e mais {len(vulnerabilities) - 3} vulnerabilidades.")
            else:
                summary.append("ℹ️  Nmap: Dados não parseados disponíveis.")

        # Resumo Nikto
        if 'nikto' in target_results_tools:
            nikto_data = target_results_tools['nikto']
            if nikto_data.get('skipped'):
                summary.append(f"⏭️  Nikto: Pulado - {nikto_data.get('reason', 'Motivo não especificado')}")
            elif 'error' in nikto_data:
                summary.append(f"❌ Nikto: {nikto_data['error']}")
            else:
                target_has_web = True
                total_findings = nikto_data.get('total_findings', 0)
                total_web_findings += total_findings
                urls_scanned = nikto_data.get('urls_scanned', [])
                
                summary.append(f"🌐 Nikto: {total_findings} achados em {len(urls_scanned)} URL(s)")
                
                for url_result in nikto_data.get('results', [])[:2]:  # Primeiras 2 URLs
                    url = url_result.get('url', 'N/A')
                    parsed = url_result.get('parsed', {})
                    findings = parsed.get('findings', [])
                    
                    if findings:
                        summary.append(f"   📍 {url}:")
                        for finding in findings[:3]:  # Primeiros 3 achados por URL
                            severity = finding.get('severity', 'info')
                            desc = finding.get('description', 'N/A')[:80]
                            severity_icon = {'high': '🔴', 'medium': '🟡', 'low': '🔵', 'info': 'ℹ️'}.get(severity, 'ℹ️')
                            summary.append(f"      {severity_icon} {desc}")

        # Resumo Dirb
        if 'dirb' in target_results_tools:
            dirb_data = target_results_tools['dirb']
            if dirb_data.get('skipped'):
                summary.append(f"⏭️  Dirb: Pulado - {dirb_data.get('reason', 'Motivo não especificado')}")
            elif 'error' in dirb_data:
                summary.append(f"❌ Dirb: {dirb_data['error']}")
            else:
                target_has_web = True
                total_dirs = dirb_data.get('total_directories', 0)
                total_files = dirb_data.get('total_files', 0)
                
                summary.append(f"📁 Dirb: {total_dirs} diretórios, {total_files} arquivos encontrados")
                
                for url_result in dirb_data.get('results', [])[:2]:  # Primeiras 2 URLs
                    url = url_result.get('url', 'N/A')
                    parsed = url_result.get('parsed', {})
                    interesting_files = [f for f in parsed.get('files_found', []) if f.get('interesting', False)]
                    
                    if interesting_files:
                        summary.append(f"   📍 {url} - Arquivos interessantes:")
                        for file_info in interesting_files[:5]:  
                            path = file_info.get('path', 'N/A')
                            status = file_info.get('status_code', 'N/A')
                            summary.append(f"      📄 {path} (HTTP {status})")

        if 'testssl' in target_results_tools:
            testssl_data = target_results_tools['testssl']
            if 'error' in testssl_data:
                summary.append(f"❌ TestSSL: {testssl_data['error']}")
            elif 'parsed' in testssl_data and testssl_data['parsed']['issues']:
                issues = testssl_data['parsed']['issues']
                summary.append(f"🔒 TestSSL: {len(issues)} problemas de SSL/TLS encontrados.")
                for issue in issues[:2]:
                    summary.append(f"   - [{issue.get('type', 'N/A').upper()}] {issue.get('message', 'N/A')[:80]}")

        if 'searchsploit' in target_results_tools:
            ssploit_data = target_results_tools['searchsploit']
            if 'error' in ssploit_data:
                summary.append(f"❌ SearchSploit: {ssploit_data['error']}")
            elif 'parsed' in ssploit_data and ssploit_data['parsed']['count'] > 0:
                count = ssploit_data['parsed']['count']
                summary.append(f"💥 SearchSploit: {count} exploits potenciais encontrados.")

        if 'enum4linux' in target_results_tools:
            enum_data = target_results_tools['enum4linux']
            if 'error' in enum_data:
                summary.append(f"❌ Enum4linux: {enum_data['error']}")
            elif 'parsed' in enum_data:
                parsed = enum_data['parsed']
                shares = len(parsed.get('shares', []))
                users = len(parsed.get('users', []))
                summary.append(f"🐧 Enum4linux: {shares} compartilhamentos, {users} usuários encontrados.")

        if 'snmp' in target_results_tools:
            snmp_data = target_results_tools['snmp']
            if 'error' in snmp_data:
                summary.append(f"❌ SNMP: {snmp_data['error']}")
            elif 'parsed' in snmp_data and snmp_data['parsed']['sysdescr']:
                summary.append(f"📡 SNMP: Comunidade encontrada. Descrição: {snmp_data['parsed']['sysdescr'][:80]}")
        
        if target_has_web:
            hosts_with_web += 1

    # Estatísticas finais
    summary.append(f"\n{'='*60}")
    summary.append("ESTATÍSTICAS GERAIS")
    summary.append(f"{'='*60}")
    summary.append(f"🖥️  Hosts ativos: {hosts_up}")
    summary.append(f"🌐 Hosts com serviços web: {hosts_with_web}")
    summary.append(f"🔌 Total de portas abertas: {total_ports}")
    summary.append(f"⚠️  Total de vulnerabilidades (Nmap): {total_vulnerabilities}")
    summary.append(f"🔍 Total de achados web (Nikto): {total_web_findings}")
    summary.append(f"🔒 Total de problemas SSL/TLS: {stats['total_ssl_issues']}")
    
    summary.append(f"\n📊 Relatório gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}")
    summary.append("=" * 60)
    
    return "\n".join(summary)

def generate_html_report(results: Dict, logger_param: logging.Logger) -> str:
    """Gera relatório em formato HTML profissional"""
    global logger
    logger = logger_param
    
    scan_info = results.get('scan_info', {})
    
    # Calcula estatísticas
    stats = calculate_statistics(results)
    
    html_content = f"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScan Suite - Relatório de Segurança</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background-color: #f5f5f5;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 1.2em;
            opacity: 0.9;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .stat-card {{
            background: white;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-card h3 {{
            font-size: 2em;
            color: #667eea;
            margin-bottom: 10px;
        }}
        
        .stat-card p {{
            color: #666;
            font-size: 1.1em;
        }}
        
        .section {{
            background: white;
            margin-bottom: 30px;
            border-radius: 10px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            overflow: hidden;
        }}
        
        .section-header {{
            background: #f8f9fa;
            padding: 20px;
            border-bottom: 1px solid #dee2e6;
        }}
        
        .section-header h2 {{
            color: #495057;
            font-size: 1.5em;
        }}
        
        .section-content {{
            padding: 20px;
        }}
        
        .target-card {{
            border: 1px solid #dee2e6;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }}
        
        .target-header {{
            background: #343a40;
            color: white;
            padding: 15px;
            font-weight: bold;
            font-size: 1.2em;
        }}
        
        .target-content {{
            padding: 20px;
        }}
        
        .tool-result {{
            margin-bottom: 25px;
            padding: 15px;
            border-left: 4px solid #28a745;
            background: #f8f9fa;
            border-radius: 0 5px 5px 0;
        }}
        
        .tool-result.error {{
            border-left-color: #dc3545;
            background: #f8d7da;
        }}
        
        .tool-result.skipped {{
            border-left-color: #ffc107;
            background: #fff3cd;
        }}
        
        .tool-result h4 {{
            margin-bottom: 10px;
            color: #495057;
        }}
        
        .ports-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 10px;
            margin: 15px 0;
        }}
        
        .port-item {{
            background: white;
            padding: 10px;
            border-radius: 5px;
            border: 1px solid #dee2e6;
            font-family: monospace;
        }}
        
        .vulnerability {{
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 5px;
            padding: 10px;
            margin: 5px 0;
        }}
        
        .vulnerability.high {{
            background: #f8d7da;
            border-color: #f5c6cb;
        }}
        
        .vulnerability.medium {{
            background: #fff3cd;
            border-color: #ffeaa7;
        }}
        
        .vulnerability.low {{
            background: #d1ecf1;
            border-color: #bee5eb;
        }}
        
        .finding-list {{
            list-style: none;
            padding: 0;
        }}
        
        .finding-list li {{
            padding: 8px;
            margin: 5px 0;
            background: #f8f9fa;
            border-radius: 4px;
            border-left: 3px solid #6c757d;
        }}
        
        .severity-high {{ border-left-color: #dc3545 !important; }}
        .severity-medium {{ border-left-color: #ffc107 !important; }}
        .severity-low {{ border-left-color: #17a2b8 !important; }}
        .severity-info {{ border-left-color: #6c757d !important; }}
        
        .footer {{
            text-align: center;
            padding: 20px;
            color: #6c757d;
            border-top: 1px solid #dee2e6;
            margin-top: 30px;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 10px;
            }}
            
            .header h1 {{
                font-size: 2em;
            }}
            
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>VulnScan Suite</h1>
            <div class="subtitle">Relatório de Análise de Vulnerabilidades</div>
            <div style="margin-top: 15px; font-size: 0.9em;">
                Gerado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <h3>{stats['total_targets']}</h3>
                <p>Targets Analisados</p>
            </div>
            <div class="stat-card">
                <h3>{stats['hosts_up']}</h3>
                <p>Hosts Ativos</p>
            </div>
            <div class="stat-card">
                <h3>{stats['total_ports']}</h3>
                <p>Portas Abertas</p>
            </div>
            <div class="stat-card">
                <h3>{stats['total_vulnerabilities']}</h3>
                <p>Vulnerabilidades</p>
            </div>
            <div class="stat-card"><h3>{stats['total_web_findings']}</h3><p>Achados Web</p></div>
            <div class="stat-card"><h3>{stats['total_ssl_issues']}</h3><p>Problemas SSL</p></div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>📋 Informações do Scan</h2>
            </div>
            <div class="section-content">
                <p><strong>Data de início:</strong> {scan_info.get('start_time', 'N/A')}</p>
                <p><strong>Data de término:</strong> {scan_info.get('end_time', 'N/A')}</p>
                <p><strong>Ferramentas utilizadas:</strong> {', '.join(scan_info.get('tools_used', []))}</p>
                <p><strong>Intensidade do scan:</strong> {scan_info.get('scan_intensity', 'N/A')}</p>
                <p><strong>Descoberta de rede:</strong> {'Habilitada' if scan_info.get('network_discovery', False) else 'Desabilitada'}</p>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header">
                <h2>🎯 Resultados por Target</h2>
            </div>
            <div class="section-content">
                {generate_targets_html(results)}
            </div>
        </div>
        
        <div class="footer">
            <p>Relatório gerado pelo VulnScan Suite</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html_content

def generate_targets_html(results: Dict) -> str:
    """Gera HTML para os resultados de cada target"""
    targets_html = []
    
    for target, target_results in results.get('results', {}).items():
        target_html = f"""
        <div class="target-card">
            <div class="target-header">
                🎯 {target}
            </div>
            <div class="target-content">
                {generate_target_tools_html(target_results)}
            </div>
        </div>
        """
        targets_html.append(target_html)
    
    return ''.join(targets_html)

def generate_target_tools_html(target_results: Dict) -> str:
    """Gera HTML para os resultados das ferramentas de um target"""
    tools_html = []
    
    # Nmap
    if 'nmap' in target_results:
        nmap_html = generate_nmap_html(target_results['nmap'])
        tools_html.append(nmap_html)
    
    # Nikto
    if 'nikto' in target_results:
        nikto_html = generate_nikto_html(target_results['nikto'])
        tools_html.append(nikto_html)
    
    # Dirb
    if 'dirb' in target_results:
        dirb_html = generate_dirb_html(target_results['dirb'])
        tools_html.append(dirb_html)

    if 'testssl' in target_results: tools_html.append(generate_testssl_html(target_results['testssl']))
    if 'searchsploit' in target_results: tools_html.append(generate_searchsploit_html(target_results['searchsploit']))
    if 'enum4linux' in target_results: tools_html.append(generate_enum4linux_html(target_results['enum4linux']))
    if 'snmp' in target_results: tools_html.append(generate_snmp_html(target_results['snmp']))
    
    return ''.join(tools_html)

def generate_nmap_html(nmap_data: Dict) -> str:
    """Gera HTML para resultados do Nmap"""
    if 'error' in nmap_data:
        return f"""
        <div class="tool-result error">
            <h4>🔍 Nmap</h4>
            <p>❌ Erro: {nmap_data['error']}</p>
        </div>
        """
    
    if 'parsed' not in nmap_data:
        return f"""
        <div class="tool-result">
            <h4>🔍 Nmap</h4>
            <p>ℹ️ Dados não parseados disponíveis</p>
        </div>
        """
    
    parsed = nmap_data['parsed']
    host_status = parsed.get('host_status', 'unknown')
    open_ports = parsed.get('open_ports', [])
    vulnerabilities = parsed.get('vulnerabilities', [])
    
    ports_html = ""
    if open_ports:
        ports_items = []
        for port in open_ports[:20]:  # Primeiras 20 portas
            port_html = f"""
            <div class="port-item">
                <strong>{port.get('port', 'N/A')}</strong><br>
                {port.get('service', 'N/A')}<br>
                <small>{port.get('version', '')}</small>
            </div>
            """
            ports_items.append(port_html)
        
        ports_html = f"""
        <h5>🔌 Portas Abertas ({len(open_ports)})</h5>
        <div class="ports-grid">
            {''.join(ports_items)}
        </div>
        """
        
        if len(open_ports) > 20:
            ports_html += f"<p><em>... e mais {len(open_ports) - 20} portas.</em></p>"
    
    vulns_html = ""
    if vulnerabilities:
        vulns_items = []
        for vuln in vulnerabilities:  # Primeiras 10 vulnerabilidades
            vuln_html = f"""
            <div class="vulnerability">
                <strong>Porta {vuln.get('port', 'N/A')}:</strong> {vuln.get('description', 'N/A')}
            </div>
            """
            vulns_items.append(vuln_html)
        
        vulns_html = f"""
        <h5>⚠️ Vulnerabilidades ({len(vulnerabilities)})</h5>
        {''.join(vulns_items)}
        """
        
        if len(vulnerabilities) > 10:
            vulns_html += f"<p><em>... e mais {len(vulnerabilities) - 10} vulnerabilidades.</em></p>"
    
    os_info = parsed.get('os_info', '')
    os_html = f"<p><strong>💻 Sistema Operacional:</strong> {os_info}</p>" if os_info else ""
    
    mac_address = parsed.get('mac_address', '')
    mac_html = f"<p><strong>🏷️ MAC Address:</strong> {mac_address}</p>" if mac_address else ""
    
    return f"""
    <div class="tool-result">
        <h4>🔍 Nmap</h4>
        <p><strong>🖥️ Status do Host:</strong> {host_status.upper()}</p>
        {os_html}
        {mac_html}
        {ports_html}
        {vulns_html}
    </div>
    """

def generate_nikto_html(nikto_data: Dict) -> str:
    """Gera HTML para resultados do Nikto"""
    if nikto_data.get('skipped'):
        return f"""
        <div class="tool-result skipped">
            <h4>🌐 Nikto</h4>
            <p>⏭️ Pulado: {nikto_data.get('reason', 'Motivo não especificado')}</p>
        </div>
        """
    
    if 'error' in nikto_data:
        return f"""
        <div class="tool-result error">
            <h4>🌐 Nikto</h4>
            <p>❌ Erro: {nikto_data['error']}</p>
        </div>
        """
    
    total_findings = nikto_data.get('total_findings', 0)
    urls_scanned = nikto_data.get('urls_scanned', [])
    
    findings_html = ""
    for url_result in nikto_data.get('results', []):
        url = url_result.get('url', 'N/A')
        parsed = url_result.get('parsed', {})
        findings = parsed.get('findings', [])
        
        if findings:
            findings_items = []
            for finding in findings[:15]:  # Primeiros 15 achados por URL
                severity = finding.get('severity', 'info')
                desc = finding.get('description', 'N/A')
                findings_items.append(f'<li class="severity-{severity}">{desc}</li>')
            
            findings_html += f"""
            <h5>📍 {url}</h5>
            <ul class="finding-list">
                {''.join(findings_items)}
            </ul>
            """
            
            if len(findings) > 15:
                findings_html += f"<p><em>... e mais {len(findings) - 15} achados.</em></p>"
    
    return f"""
    <div class="tool-result">
        <h4>🌐 Nikto</h4>
        <p><strong>📊 Total de achados:</strong> {total_findings} em {len(urls_scanned)} URL(s)</p>
        {findings_html}
    </div>
    """

def generate_dirb_html(dirb_data: Dict) -> str:
    """Gera HTML para resultados do Dirb"""
    if dirb_data.get('skipped'):
        return f"""
        <div class="tool-result skipped">
            <h4>📁 Dirb</h4>
            <p>⏭️ Pulado: {dirb_data.get('reason', 'Motivo não especificado')}</p>
        </div>
        """
    
    if 'error' in dirb_data:
        return f"""
        <div class="tool-result error">
            <h4>📁 Dirb</h4>
            <p>❌ Erro: {dirb_data['error']}</p>
        </div>
        """
    
    total_dirs = dirb_data.get('total_directories', 0)
    total_files = dirb_data.get('total_files', 0)
    
    results_html = ""
    for url_result in dirb_data.get('results', []):
        url = url_result.get('url', 'N/A')
        parsed = url_result.get('parsed', {})
        
        interesting_files = [f for f in parsed.get('files_found', []) if f.get('interesting', False)]
        directories = parsed.get('directories_found', [])
        
        if interesting_files or directories:
            results_html += f"<h5>📍 {url}</h5>"
            
            if directories:
                dir_items = [f'<li>📁 {d.get("path", "N/A")}</li>' for d in directories[:10]]
                results_html += f"""
                <h6>Diretórios ({len(directories)})</h6>
                <ul class="finding-list">
                    {''.join(dir_items)}
                </ul>
                """
                if len(directories) > 10:
                    results_html += f"<p><em>... e mais {len(directories) - 10} diretórios.</em></p>"
            
            if interesting_files:
                file_items = []
                for file_info in interesting_files[:10]:
                    path = file_info.get('path', 'N/A')
                    status = file_info.get('status_code', 'N/A')
                    file_items.append(f'<li>📄 {path} <span style="color: #666;">(HTTP {status})</span></li>')
                
                results_html += f"""
                <h6>Arquivos Interessantes ({len(interesting_files)})</h6>
                <ul class="finding-list">
                    {''.join(file_items)}
                </ul>
                """
                if len(interesting_files) > 10:
                    results_html += f"<p><em>... e mais {len(interesting_files) - 10} arquivos.</em></p>"
    
    return f"""
    <div class="tool-result">
        <h4>📁 Dirb</h4>
        <p><strong>📊 Resultados:</strong> {total_dirs} diretórios, {total_files} arquivos</p>
        {results_html}
    </div>
    """


def generate_testssl_html(data: Dict) -> str:
    """Gera HTML para resultados do TestSSL.sh"""
    if 'error' in data:
        return f'<div class="tool-result error"><h4>🔒 TestSSL.sh</h4><p>❌ Erro: {data["error"]}</p></div>'
    
    parsed = data.get('parsed', {})
    if not parsed or not parsed.get('issues'):
        return '<div class="tool-result"><h4>🔒 TestSSL.sh</h4><p>✅ Nenhum problema significativo encontrado.</p></div>'

    issues = parsed['issues']
    items_html = []
    for issue in issues[:15]:
        sev_class = "vulnerability medium" if issue['type'] == 'warning' else "vulnerability"
        items_html.append(f'<div class="{sev_class}" style="padding: 5px 10px; font-size: 0.9em;"><strong>[{issue["type"].upper()}]</strong> {issue["message"]}</div>')
    
    if len(issues) > 15:
        items_html.append(f"<p><em>... e mais {len(issues) - 15} problemas.</em></p>")

    return f"""
    <div class="tool-result">
        <h4>🔒 TestSSL.sh</h4>
        <p><strong>📊 Total de problemas encontrados:</strong> {len(issues)}</p>
        {''.join(items_html)}
    </div>
    """

def generate_searchsploit_html(data: Dict) -> str:
    """Gera HTML para resultados do SearchSploit"""
    if 'error' in data:
        return f'<div class="tool-result error"><h4>💥 SearchSploit</h4><p>❌ Erro: {data["error"]}</p></div>'

    parsed = data.get('parsed', {})
    if not parsed or parsed.get('count', 0) == 0:
        return '<div class="tool-result"><h4>💥 SearchSploit</h4><p>✅ Nenhum exploit encontrado para o termo de busca.</p></div>'

    results = parsed['results']
    items_html = [f'<li>{res["raw"]}</li>' for res in results[:15]]
    
    if len(results) > 15:
        items_html.append(f"<li><em>... e mais {len(results) - 15} resultados.</em></li>")

    return f"""
    <div class="tool-result">
        <h4>💥 SearchSploit</h4>
        <p><strong>📊 Total de exploits encontrados:</strong> {parsed['count']}</p>
        <ul class="finding-list">{''.join(items_html)}</ul>
    </div>
    """

def generate_enum4linux_html(data: Dict) -> str:
    """Gera HTML para resultados do Enum4linux"""
    if 'error' in data:
        return f'<div class="tool-result error"><h4>🐧 Enum4linux</h4><p>❌ Erro: {data["error"]}</p></div>'

    parsed = data.get('parsed', {})
    if not parsed or (not parsed.get('shares') and not parsed.get('users')):
        return '<div class="tool-result"><h4>🐧 Enum4linux</h4><p>✅ Nenhuma informação significativa (shares, usuários) enumerada.</p></div>'

    html = "<div class='tool-result'><h4>🐧 Enum4linux</h4>"
    if parsed.get('os'): html += f"<p><strong>Sistema Operacional:</strong> {parsed['os']}</p>"
    
    if parsed.get('shares'):
        html += f"<h5>Compartilhamentos ({len(parsed['shares'])})</h5><ul class='finding-list'>"
        for item in parsed['shares'][:10]: html += f"<li>{item}</li>"
        html += "</ul>"

    if parsed.get('users'):
        html += f"<h5>Usuários ({len(parsed['users'])})</h5><ul class='finding-list'>"
        for item in parsed['users'][:10]: html += f"<li>{item}</li>"
        html += "</ul>"
    
    html += "</div>"
    return html

def generate_snmp_html(data: Dict) -> str:
    """Gera HTML para resultados do SNMP Scan"""
    if 'error' in data:
        return f'<div class="tool-result error"><h4>📡 SNMP Scan</h4><p>❌ Erro: {data["error"]}</p></div>'

    parsed = data.get('parsed', {})
    if not parsed or not parsed.get('sysdescr'):
        return '<div class="tool-result"><h4>📡 SNMP Scan</h4><p>✅ Nenhuma resposta SNMP obtida.</p></div>'

    html = "<div class='tool-result'><h4>📡 SNMP Scan</h4>"
    if parsed.get('community_default'): html += '<p><strong style="color: #dc3545;">Comunidade padrão "public" encontrada!</strong></p>'
    if parsed.get('sysdescr'): html += f"<p><strong>Descrição do Sistema:</strong> {parsed['sysdescr']}</p>"
    if parsed.get('contact'): html += f"<p><strong>Contato:</strong> {parsed['contact']}</p>"
    if parsed.get('location'): html += f"<p><strong>Localização:</strong> {parsed['location']}</p>"
    html += "</div>"
    return html    

def calculate_statistics(results: Dict) -> Dict:
    """Calcula estatísticas gerais dos resultados"""
    stats = {
        'total_targets': len(results.get('results', {})),
        'hosts_up': 0,
        'total_ports': 0,
        'total_vulnerabilities': 0,
        'total_web_findings': 0,
        'hosts_with_web': 0,
        'total_ssl_issues': 0
    }
    
    for target, target_results in results.get('results', {}).items():
        # Nmap stats
        if 'nmap' in target_results and 'parsed' in target_results['nmap']:
            parsed = target_results['nmap']['parsed']
            if parsed.get('host_status') == 'up':
                stats['hosts_up'] += 1
            stats['total_ports'] += len(parsed.get('open_ports', []))
            stats['total_vulnerabilities'] += len(parsed.get('vulnerabilities', []))
        
        # Web scanners stats
        has_web = False
        if 'nikto' in target_results and not target_results['nikto'].get('skipped'):
            has_web = True
            stats['total_web_findings'] += target_results['nikto'].get('total_findings', 0)
        
        if 'dirb' in target_results and not target_results['dirb'].get('skipped'):
            has_web = True

        if 'testssl' in target_results and 'parsed' in target_results['testssl']:
            stats['total_ssl_issues'] += len(target_results['testssl']['parsed'].get('issues', []))
        
        if has_web:
            stats['hosts_with_web'] += 1
    
    return stats

def save_results(results: Dict, report_format: str, logger_param: logging.Logger, base_report_dir: str = "reports"):
    """Salva resultados em diferentes formatos"""
    global logger
    logger = logger_param
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    try:
        if report_format == 'json':
            filename = os.path.join(base_report_dir, 'json', f"vulnscan_report_{timestamp}.json")
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info(f"Relatório JSON salvo: {filename}")

        elif report_format == 'txt':
            filename = os.path.join(base_report_dir, 'txt', f"vulnscan_summary_{timestamp}.txt")
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            summary_content = generate_summary_report(results, logger_param)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(summary_content)
            logger.info(f"Relatório TXT salvo: {filename}")
        
        elif report_format == 'html':
            filename = os.path.join(base_report_dir, 'html', f"vulnscan_report_{timestamp}.html")
            os.makedirs(os.path.dirname(filename), exist_ok=True)
            html_content = generate_html_report(results, logger_param)
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            logger.info(f"Relatório HTML salvo: {filename}")
        
        elif report_format == 'pdf':
            html_content = generate_html_report(results, logger_param)
            html_filename = os.path.join(base_report_dir, 'html', f"vulnscan_report_{timestamp}.html")
            pdf_filename = os.path.join(base_report_dir, 'pdf', f"vulnscan_report_{timestamp}.pdf")
            
            os.makedirs(os.path.dirname(html_filename), exist_ok=True)
            os.makedirs(os.path.dirname(pdf_filename), exist_ok=True)
            
            with open(html_filename, 'w', encoding='utf-8') as f:
                f.write(html_content)

            try:
                import weasyprint
                weasyprint.HTML(filename=html_filename).write_pdf(pdf_filename)
                logger.info(f"Relatório PDF salvo: {pdf_filename}")
            except ImportError:
                logger.warning("WeasyPrint não disponível. Instalando...")
                import subprocess
                subprocess.run(['pip', 'install', 'weasyprint'], check=True)
                import weasyprint
                weasyprint.HTML(filename=html_filename).write_pdf(pdf_filename)
                logger.info(f"Relatório PDF salvo: {pdf_filename}")
            except Exception as e:
                logger.error(f"Erro ao gerar PDF: {str(e)}. HTML salvo em: {html_filename}")
        
    except Exception as e:
        logger.error(f"Erro ao salvar relatório {report_format.upper()}: {str(e)}")

def estimate_scan_time(num_targets: int, tools: List[str], intensity: str, logger_param: logging.Logger) -> str:
    """Estima tempo de execução do scan"""
    global logger
    logger = logger_param 

    base_times_per_tool = { 
        'nmap': {'quick': 1, 'basic': 3, 'normal': 5, 'comprehensive': 10},
        'nikto': {'quick': 2, 'basic': 5, 'normal': 8, 'comprehensive': 12},
        'dirb': {'quick': 2, 'basic': 5, 'normal': 8, 'comprehensive': 10}  
    }
    
    intensity_map = {
        'quick': 'quick',
        'basic': 'basic',
        'normal': 'normal',
        'comprehensive': 'comprehensive' 
    }
    effective_intensity = intensity_map.get(intensity, 'basic')

    total_minutes = 0
    for tool in tools:
        if tool in base_times_per_tool:
            tool_times = base_times_per_tool[tool]
            time_for_tool = tool_times.get(effective_intensity, tool_times.get('basic', 5)) 
            total_minutes += time_for_tool
        else:
            total_minutes += 5

    total_minutes *= num_targets
    
    if len(tools) > 3:
         total_minutes *= (len(tools) / 3) * 0.7 

    if total_minutes == 0 and num_targets > 0: 
        total_minutes = num_targets * 2 

    if total_minutes < 1:
        return "< 1 minuto"
    if total_minutes < 60:
        return f"~{int(round(total_minutes))} minutos"
    else:
        hours = int(total_minutes // 60)
        minutes = int(round(total_minutes % 60))
        return f"~{hours}h{minutes:02d}m"

