# VulnScan Suite


##  Características

- **Descoberta automática**: Suporte a CIDR (ex: `192.168.1.0/24`)
- **Scanners integrados**: Nmap, Nikto, Dirb, TestSSL, Enum4Linux, SNMP, SearchSploit
- **Relatórios múltiplos**: JSON, TXT, HTML, PDF
- **Execução inteligente**: Scanners web só em hosts HTTP/HTTPS
- **Análise de SSL/TLS**: Verificação de configurações e vulnerabilidades SSL
- **Enumeração SMB**: Análise detalhada de serviços Windows/Samba
- **Busca de exploits**: Integração com SearchSploit para CVEs encontradas

##  Instalação

```bash
# Instalar ferramentas do sistema
sudo apt install nmap nikto dirb enum4linux snmp-mibs-downloader python3 python3-pip

# Instalar TestSSL (opcional)
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
sudo ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

# Instalar SearchSploit (opcional)
sudo apt install exploitdb

# Instalar dependências Python
pip3 install -r requirements.txt

# Criar configuração padrão
python3 vulnscan_suite.py --create-config
```

##  Uso Básico

### Scans Simples

```bash
# Scan de IP único com ferramentas padrão (nmap, nikto, dirb)
python3 vulnscan_suite.py -t 192.168.1.100

# Scan de rede completa com descoberta automática
python3 vulnscan_suite.py -t 192.168.1.0/24

# Múltiplos targets
python3 vulnscan_suite.py -t 192.168.1.100 -t 10.0.0.50 -t example.com
```

### Scans por Intensidade

```bash
# Scan rápido (apenas Nmap, top 100 portas)
python3 vulnscan_suite.py -t 192.168.1.0/24 --quick

# Scan básico com detecção de versões (padrão)
python3 vulnscan_suite.py -t 192.168.1.100 --intensity basic

# Scan normal com scripts padrão do Nmap
python3 vulnscan_suite.py -t 192.168.1.100 --intensity normal

# Scan abrangente com scripts de vulnerabilidade
python3 vulnscan_suite.py -t 192.168.1.100 --intensity comprehensive
```

### Scans com Ferramentas Específicas

```bash
# Apenas Nmap
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap

# Foco em vulnerabilidades web
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap nikto dirb

# Análise SSL/TLS
python3 vulnscan_suite.py -t https://example.com --tools nmap testssl

# Enumeração SMB/NetBIOS
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap enum4linux

# Scan SNMP
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap snmp

# Busca de exploits para vulnerabilidades encontradas
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap searchsploit

# Todas as ferramentas disponíveis
python3 vulnscan_suite.py -t 192.168.1.100 --tools nmap nikto dirb testssl enum4linux snmp searchsploit
```

### Opções Avançadas

```bash
# Teste de conectividade antes do scan
python3 vulnscan_suite.py -t 192.168.1.0/24 --test-connection

# Desabilitar descoberta automática de hosts
python3 vulnscan_suite.py -t 192.168.1.0/24 --no-discovery

# Usar arquivo de configuração personalizado
python3 vulnscan_suite.py -t 192.168.1.100 --config custom_config.json

# Scan de targets de arquivo
python3 vulnscan_suite.py -f targets.txt --intensity comprehensive
```

### Exemplos

```bash
# Auditoria completa de rede corporativa
python3 vulnscan_suite.py -t 10.0.0.0/24 --intensity comprehensive --test-connection

# Análise de servidor web
python3 vulnscan_suite.py -t webapp.company.com --tools nmap nikto dirb testssl

# Pentest de infraestrutura Windows
python3 vulnscan_suite.py -t 192.168.1.0/24 --tools nmap enum4linux snmp --intensity normal

# Descoberta rápida de rede
python3 vulnscan_suite.py -t 172.16.0.0/16 --quick --test-connection
```

##  Níveis de Intensidade

- **quick**: Scan rápido com Nmap (top 100 portas)
- **basic**: Scan básico com detecção de versões (padrão)
- **normal**: Scan com scripts padrão do Nmap
- **comprehensive**: Scan completo com scripts de vulnerabilidade

##  Estrutura de Arquivos

```
vulnscan_suite/
├── vulnscan_suite.py          # Script principal
├── modules/                   # Módulos do scanner
├── config/                    # Configurações
├── logs/                      # Logs da aplicação
├── reports/                   # Relatórios gerados
│   ├── json/
│   ├── txt/
│   ├── html/
│   └── pdf/
└── requirements.txt          # Dependências Python
```

##  Formatos de Relatório

- **JSON**: Dados estruturados para automação
- **TXT**: Resumo textual com estatísticas
- **HTML**: Interface web responsiva com gráficos
- **PDF**: Conversão automática para apresentações

##  Configuração

Edite `config/tools_config.json` para personalizar as ferramentas:

```json
{
  "nmap": {
    "enabled": true,
    "timing": "-T4",
    "max_ports": "1000"
  },
  "nikto": {
    "enabled": true,
    "max_time": 600
  },
  "dirb": {
    "enabled": true,
    "wordlist": "/usr/share/dirb/wordlists/common.txt"
  },
  "testssl": {
    "enabled": true,
    "path": "testssl.sh",
    "timeout": 300
  },
  "enum4linux": {
    "enabled": true,
    "path": "enum4linux",
    "timeout": 120
  },
  "snmp": {
    "enabled": true,
    "path_snmpcheck": "snmp-check",
    "community": "public"
  },
  "searchsploit": {
    "enabled": true,
    "path": "searchsploit",
    "timeout": 60
  }
}
```

##  Considerações de Segurança

- **Use apenas em redes próprias** ou com autorização explícita
- **Respeite os termos de uso** dos sistemas testados
- **Configure timeouts adequados** para evitar sobrecarga
- **Monitore o tráfego de rede** durante os scans


##  Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para detalhes.


