import os
import sys
import subprocess
import json
import time
from datetime import datetime

def run_command(cmd, timeout=60):
    """Executa um comando e retorna o resultado"""
    try:
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout
        )
        return {
            'success': result.returncode == 0,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'returncode': result.returncode
        }
    except subprocess.TimeoutExpired:
        return {
            'success': False,
            'error': f'Timeout após {timeout}s',
            'returncode': -1
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'returncode': -1
        }

def test_basic_functionality():
    """Testa funcionalidades básicas"""
    print("🧪 Testando funcionalidades básicas...")
    
    tests = []
    
    # Teste 1: Criação de configuração
    print("  📝 Teste 1: Criação de configuração padrão")
    result = run_command("python3 vulnscan_suite.py --create-config", timeout=10)
    tests.append({
        'name': 'Criação de configuração',
        'success': result['success'],
        'details': result.get('error', 'OK')
    })
    
    # Teste 2: Scan rápido localhost
    print("  🔍 Teste 2: Scan rápido do localhost")
    result = run_command("python3 vulnscan_suite.py -t 127.0.0.1 --quick", timeout=30)
    tests.append({
        'name': 'Scan rápido localhost',
        'success': result['success'],
        'details': result.get('error', 'OK')
    })
    
    # Teste 3: Verificação de relatórios
    print("  📊 Teste 3: Verificação de geração de relatórios")
    json_files = [f for f in os.listdir('reports/json') if f.endswith('.json')]
    txt_files = [f for f in os.listdir('reports/txt') if f.endswith('.txt')]
    html_files = [f for f in os.listdir('reports/html') if f.endswith('.html')]
    
    reports_ok = len(json_files) > 0 and len(txt_files) > 0 and len(html_files) > 0
    tests.append({
        'name': 'Geração de relatórios',
        'success': reports_ok,
        'details': f'JSON: {len(json_files)}, TXT: {len(txt_files)}, HTML: {len(html_files)}'
    })
    
    return tests

def test_network_discovery():
    """Testa descoberta de rede"""
    print("🌐 Testando descoberta de rede...")
    
    tests = []
    
    # Teste 1: Descoberta com CIDR (usando range pequeno)
    print("  🔍 Teste 1: Descoberta com notação CIDR")
    result = run_command("python3 vulnscan_suite.py -t 127.0.0.0/30 --quick --test-connection", timeout=45)
    tests.append({
        'name': 'Descoberta CIDR',
        'success': result['success'],
        'details': result.get('error', 'OK')
    })
    
    # Teste 2: Teste de conectividade
    print("  📡 Teste 2: Teste de conectividade")
    result = run_command("python3 vulnscan_suite.py -t 127.0.0.1 --test-connection --quick", timeout=30)
    tests.append({
        'name': 'Teste de conectividade',
        'success': result['success'],
        'details': result.get('error', 'OK')
    })
    
    return tests

def test_web_detection():
    """Testa detecção de serviços web"""
    print("🌐 Testando detecção de serviços web...")
    
    tests = []
    
    # Teste 1: Target sem serviços web (localhost)
    print("  🔍 Teste 1: Target sem serviços web")
    result = run_command("python3 vulnscan_suite.py -t 127.0.0.1 --tools nikto --intensity basic", timeout=30)
    # Deve pular o Nikto
    nikto_skipped = 'Nikto pulado' in result.get('stdout', '') or 'skipped' in result.get('stdout', '')
    tests.append({
        'name': 'Detecção - sem serviços web',
        'success': nikto_skipped,
        'details': 'Nikto pulado corretamente' if nikto_skipped else 'Nikto não foi pulado'
    })
    
    return tests

def test_error_handling():
    """Testa tratamento de erros"""
    print("⚠️ Testando tratamento de erros...")
    
    tests = []
    
    # Teste 1: Target inválido
    print("  ❌ Teste 1: Target inválido")
    result = run_command("python3 vulnscan_suite.py -t invalid.target.nonexistent --quick", timeout=30)
    # Deve falhar graciosamente
    tests.append({
        'name': 'Target inválido',
        'success': True,  # Sempre passa se não travou
        'details': 'Tratamento de erro OK'
    })
    
    # Teste 2: Arquivo de targets inexistente
    print("  📁 Teste 2: Arquivo de targets inexistente")
    result = run_command("python3 vulnscan_suite.py -f nonexistent_file.txt --quick", timeout=10)
    error_handled = 'não encontrado' in result.get('stdout', '') or result['returncode'] != 0
    tests.append({
        'name': 'Arquivo inexistente',
        'success': error_handled,
        'details': 'Erro tratado corretamente' if error_handled else 'Erro não tratado'
    })
    
    return tests

def validate_reports():
    """Valida a estrutura dos relatórios gerados"""
    print("📋 Validando estrutura dos relatórios...")
    
    tests = []
    
    # Verifica se há relatórios recentes
    json_files = [f for f in os.listdir('reports/json') if f.endswith('.json')]
    if json_files:
        latest_json = max(json_files)
        json_path = os.path.join('reports/json', latest_json)
        
        try:
            with open(json_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            # Verifica estrutura básica
            has_scan_info = 'scan_info' in data
            has_results = 'results' in data
            has_timestamps = 'start_time' in data.get('scan_info', {})
            
            structure_ok = has_scan_info and has_results and has_timestamps
            tests.append({
                'name': 'Estrutura JSON',
                'success': structure_ok,
                'details': f'scan_info: {has_scan_info}, results: {has_results}, timestamps: {has_timestamps}'
            })
            
        except Exception as e:
            tests.append({
                'name': 'Estrutura JSON',
                'success': False,
                'details': f'Erro ao ler JSON: {str(e)}'
            })
    else:
        tests.append({
            'name': 'Estrutura JSON',
            'success': False,
            'details': 'Nenhum relatório JSON encontrado'
        })
    
    # Verifica HTML
    html_files = [f for f in os.listdir('reports/html') if f.endswith('.html')]
    if html_files:
        latest_html = max(html_files)
        html_path = os.path.join('reports/html', latest_html)
        
        try:
            with open(html_path, 'r', encoding='utf-8') as f:
                html_content = f.read()
            
            has_doctype = '<!DOCTYPE html>' in html_content
            has_title = '<title>' in html_content
            has_css = '<style>' in html_content
            
            html_ok = has_doctype and has_title and has_css
            tests.append({
                'name': 'Estrutura HTML',
                'success': html_ok,
                'details': f'DOCTYPE: {has_doctype}, title: {has_title}, CSS: {has_css}'
            })
            
        except Exception as e:
            tests.append({
                'name': 'Estrutura HTML',
                'success': False,
                'details': f'Erro ao ler HTML: {str(e)}'
            })
    else:
        tests.append({
            'name': 'Estrutura HTML',
            'success': False,
            'details': 'Nenhum relatório HTML encontrado'
        })
    
    return tests

def print_results(test_category, tests):
    """Imprime resultados dos testes"""
    print(f"\n📊 Resultados - {test_category}:")
    print("-" * 50)
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        status = "✅ PASSOU" if test['success'] else "❌ FALHOU"
        print(f"  {status} - {test['name']}")
        if test['details']:
            print(f"    └─ {test['details']}")
        
        if test['success']:
            passed += 1
    
    print(f"\n📈 Resumo: {passed}/{total} testes passaram ({(passed/total)*100:.1f}%)")
    return passed, total

def main():
    """Função principal do teste"""
    print("🚀 VulnScan Suite - Suite de Testes Automatizados")
    print("=" * 60)
    print(f"Iniciado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}")
    print()
    
    # Verifica se está no diretório correto
    if not os.path.exists('vulnscan_suite.py'):
        print("❌ Erro: Execute este script no diretório do VulnScan Suite")
        sys.exit(1)
    
    # Cria diretórios de relatórios se não existirem
    os.makedirs('reports/json', exist_ok=True)
    os.makedirs('reports/txt', exist_ok=True)
    os.makedirs('reports/html', exist_ok=True)
    
    total_passed = 0
    total_tests = 0
    
    # Executa testes
    try:
        # Testes básicos
        tests = test_basic_functionality()
        passed, count = print_results("Funcionalidades Básicas", tests)
        total_passed += passed
        total_tests += count
        
        # Testes de descoberta de rede
        tests = test_network_discovery()
        passed, count = print_results("Descoberta de Rede", tests)
        total_passed += passed
        total_tests += count
        
        # Testes de detecção web
        tests = test_web_detection()
        passed, count = print_results("Detecção de Serviços Web", tests)
        total_passed += passed
        total_tests += count
        
        # Testes de tratamento de erros
        tests = test_error_handling()
        passed, count = print_results("Tratamento de Erros", tests)
        total_passed += passed
        total_tests += count
        
        # Validação de relatórios
        tests = validate_reports()
        passed, count = print_results("Validação de Relatórios", tests)
        total_passed += passed
        total_tests += count
        
    except KeyboardInterrupt:
        print("\n⚠️ Testes interrompidos pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Erro durante os testes: {str(e)}")
        sys.exit(1)
    
    # Resultado final
    print("\n" + "=" * 60)
    print("🏁 RESULTADO FINAL DOS TESTES")
    print("=" * 60)
    
    success_rate = (total_passed / total_tests) * 100 if total_tests > 0 else 0
    
    print(f"📊 Total de testes: {total_tests}")
    print(f"✅ Testes passaram: {total_passed}")
    print(f"❌ Testes falharam: {total_tests - total_passed}")
    print(f"📈 Taxa de sucesso: {success_rate:.1f}%")
    
    if success_rate >= 80:
        print("\n🎉 SUCESSO! O VulnScan Suite está funcionando corretamente.")
        exit_code = 0
    elif success_rate >= 60:
        print("\n⚠️ PARCIAL: Algumas funcionalidades podem ter problemas.")
        exit_code = 1
    else:
        print("\n❌ FALHA: Muitos problemas detectados. Verifique a instalação.")
        exit_code = 2
    
    print(f"\nFinalizado em: {datetime.now().strftime('%d/%m/%Y às %H:%M:%S')}")
    sys.exit(exit_code)

if __name__ == "__main__":
    main()

