# Murayama Recon Automation Toolkit

[English](README.md) | [Português (Brasil)](README-PT-BR.md)

Toolkit modular de reconhecimento desenvolvido em Python para avaliações de segurança autorizadas, laboratórios de cybersecurity e uso educacional.

O projeto combina **componentes nativos de reconhecimento implementados em Python** com integrações opcionais de ferramentas consolidadas. O objetivo não é substituir ferramentas como Nmap ou Subfinder, mas demonstrar como diferentes etapas de reconhecimento podem ser automatizadas, validadas, correlacionadas e exportadas em um único fluxo.

> **Somente para uso autorizado.** Execute este toolkit apenas contra sistemas de sua propriedade ou para os quais você possua autorização explícita para realizar testes de segurança.

## Funcionalidades

### Componentes nativos

- Enumeração DNS (`A`, `AAAA`, `MX`, `NS`, `TXT`)
- Enumeração concorrente de subdomínios utilizando wordlists
- Detecção de wildcard DNS
- Resolução IPv4 e IPv6 de subdomínios
- Scanner TCP concorrente
- Identificação de serviços comuns
- Reconhecimento HTTP/HTTPS
- Extração do título HTML
- Fingerprinting básico de tecnologias
- Análise de security headers HTTP
- Correlação e deduplicação de subdomínios
- Geração de relatórios JSON
- Logging verbose/debug
- Testes automatizados com pytest

### Enriquecimento externo

- **Nmap** — enriquece as portas encontradas pelo scanner nativo com informações de serviço/produto/versão
- **Subfinder** — adiciona descoberta passiva de subdomínios, seguida de validação DNS realizada pelo próprio toolkit

O scanner nativo continua responsável pela descoberta inicial de portas. O Nmap é uma etapa opcional de enriquecimento. Da mesma forma, resultados passivos do Subfinder são tratados como **candidatos**, e não como ativos confirmados, até resolverem via DNS.

## Arquitetura

```text
                         Alvo
                          |
          +---------------+----------------+
          |               |                |
          v               v                v
    Enumeração DNS    Subdomínios      Scanner TCP
                          |              Nativo
                   +------+-------+        |
                   |              |        v
                   v              v       Nmap
                Nativo        Subfinder  Enrichment
                   |              |
                   |       Validação DNS
                   |              |
                   +------+-------+
                          |
                          v
                 Merge / Deduplicação
                          |
                          v
                 Reconhecimento HTTP
                          |
                 +--------+---------+
                 |                  |
                 v                  v
            Tecnologias       Security Headers
                          |
                          v
                    Relatório JSON
```

## Estrutura do projeto

```text
Murayama.ReconToolKit/
├── recon/
│   ├── __init__.py
│   ├── cli.py
│   ├── dns.py
│   ├── http.py
│   ├── logger.py
│   ├── nmap.py
│   ├── output.py
│   ├── ports.py
│   ├── subdomains.py
│   ├── subfinder.py
│   └── technologies.py
├── tests/
├── wordlists/
│   └── subdomains.txt
├── output/
├── recon.py
├── requirements.txt
├── pytest.ini
├── README.md
└── README-PT-BR.md
```

## Requisitos

- Python 3
- pip
- Nmap (opcional, necessário apenas para `--nmap`)
- Subfinder (opcional, necessário apenas para `--subfinder`)

O toolkit foi desenvolvido e testado no Windows. As ferramentas externas precisam estar disponíveis no `PATH` do sistema.

Verifique as instalações:

```bash
python --version
nmap --version
subfinder --version
```

## Instalação

Clone o repositório:

```bash
git clone <repository-url>
cd Murayama.ReconToolKit
```

Crie um ambiente virtual:

```bash
python -m venv .venv
```

Ative no Windows:

```bash
.venv\Scripts\activate
```

No Linux/macOS:

```bash
source .venv/bin/activate
```

Instale as dependências Python:

```bash
python -m pip install -r requirements.txt
```

## CLI

Para visualizar todas as opções:

```bash
python recon.py --help
```

O toolkit atualmente oferece:

```text
--dns                 Executa enumeração DNS
--subdomains          Executa enumeração nativa de subdomínios
--subfinder           Executa descoberta passiva com Subfinder
--ports               Executa scanner TCP nativo
--http                Executa reconhecimento HTTP
--wordlist PATH       Define a wordlist de subdomínios
--threads NUMBER      Define o número de threads concorrentes
--timeout SECONDS     Define o timeout de rede
--port PORT           Verifica uma única porta TCP
--port-range RANGE    Verifica um intervalo de portas TCP
--nmap                Enriquece as portas encontradas com Nmap
--output FILE         Salva os resultados em JSON
--verbose             Habilita logging verbose/debug
```

Use `python recon.py --help` como referência definitiva para a versão do código que estiver utilizando.

## Exemplos de uso

### Enumeração DNS

```bash
python recon.py example.com --dns
```

### Enumeração nativa de subdomínios

```bash
python recon.py example.com --subdomains
```

Com wordlist e parâmetros personalizados:

```bash
python recon.py example.com \
  --subdomains \
  --wordlist wordlists/subdomains.txt \
  --threads 20 \
  --timeout 1
```

### Descoberta passiva com Subfinder

```bash
python recon.py example.com \
  --subfinder \
  --threads 20 \
  --timeout 1
```

Os resultados do Subfinder são inicialmente tratados como candidatos passivos e depois validados por DNS. Isso evita que registros históricos ou desatualizados sejam automaticamente apresentados como ativos confirmados.

Durante o desenvolvimento, uma execução contra `example.com` demonstrou claramente essa diferença:

```text
[+] Passive Subdomain Discovery (Subfinder)
    Candidates discovered: 24948
    DNS validated: 1
    www.example.com -> ...
```

Os resultados das fontes passivas mudam ao longo do tempo, portanto essas quantidades são apenas um exemplo.

### Descoberta consolidada de subdomínios

Execute os mecanismos nativo e passivo:

```bash
python recon.py example.com \
  --subdomains \
  --subfinder \
  --threads 20 \
  --timeout 1
```

O toolkit deduplica os hosts e registra quais mecanismos encontraram cada ativo:

```text
[+] Consolidated Subdomain Results
    www.example.com -> ...
        Sources: native, subfinder
```

### Scanner TCP nativo

Portas comuns:

```bash
python recon.py localhost --ports
```

Uma porta específica:

```bash
python recon.py localhost --ports --port 8080
```

Intervalo de portas:

```bash
python recon.py localhost --ports --port-range 1-1024
```

### Enriquecimento com Nmap

```bash
python recon.py localhost --ports --nmap
```

A separação é proposital:

```text
Scanner nativo
      |
      v
Portas abertas
      |
      v
Enriquecimento Nmap
```

Exemplo:

```text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Nmap Service Enrichment
    8080/tcp http
        Microsoft Kestrel httpd
```

Assim, o scanner desenvolvido no projeto continua responsável pela descoberta, enquanto o Nmap complementa o resultado com fingerprinting mais profundo.

### Reconhecimento HTTP

```bash
python recon.py example.com --http
```

Com descoberta prévia de portas:

```bash
python recon.py example.com --ports --http
```

A etapa HTTP pode coletar:

```text
URL
Status HTTP
Server
Content-Type
Título HTML
Tecnologias identificadas
Security headers
```

Os headers atualmente analisados incluem:

- `Strict-Transport-Security`
- `Content-Security-Policy`
- `X-Frame-Options`
- `X-Content-Type-Options`
- `Referrer-Policy`
- `Permissions-Policy`

Um header ausente é apresentado como observação; o impacto de segurança depende do contexto da aplicação e do ambiente.

### Saída JSON

```bash
python recon.py example.com \
  --dns \
  --subdomains \
  --ports \
  --http \
  --output output/example.com.json
```

O relatório contém metadados e os resultados das etapas habilitadas, incluindo a consolidação de subdomínios quando aplicável.

Estrutura resumida:

```json
{
  "tool": "Murayama Recon Automation Toolkit",
  "version": "0.1.0",
  "target": "example.com",
  "dns": {},
  "subdomains": [],
  "subfinder": [],
  "discovered_subdomains": [],
  "ports": [],
  "nmap": [],
  "http": []
}
```

### Logging verbose

```bash
python recon.py example.com --ports --http --verbose
```

O modo verbose apresenta informações adicionais úteis para desenvolvimento e troubleshooting.

## Testes automatizados

Execute:

```bash
python -m pytest -v
```

A suíte cobre componentes como parsing de portas da CLI, comportamento do scanner, extração de títulos HTTP, análise de tecnologias/security headers e geração de JSON.

## Decisões de arquitetura

### Scanner nativo + Nmap

O projeto mantém um scanner TCP concorrente próprio em vez de delegar toda a descoberta ao Nmap. Isso demonstra programação com sockets e concorrência, enquanto permite que o Nmap seja utilizado para aquilo em que é especialmente forte: fingerprinting mais detalhado de serviços.

### Enumeração nativa + Subfinder

A enumeração DNS baseada em wordlist e a descoberta passiva oferecem perspectivas diferentes. O Subfinder amplia a cobertura passiva, enquanto o toolkit valida os candidatos por DNS antes de considerá-los confirmados.

### Correlação em vez de resultados duplicados

Quando um host é encontrado por mais de um mecanismo, o toolkit o consolida e preserva as fontes:

```json
{
  "subdomain": "www.example.com",
  "addresses": [
    "104.20.23.154",
    "172.66.147.243"
  ],
  "sources": [
    "native",
    "subfinder"
  ]
}
```

O conjunto real de endereços também pode conter IPv6.

## Roadmap

Possíveis evoluções:

- Novas fontes passivas de reconhecimento
- Perfis configuráveis de portas
- Fingerprinting de serviços mais avançado
- Inspeção TLS/certificados
- Análise da cadeia de redirects HTTP
- Novas assinaturas de tecnologias
- Relatórios CSV/HTML
- Expansão dos testes automatizados
- CI com verificações de segurança e qualidade
- Empacotamento como CLI Python instalável

## Uso ético

Reconhecimento pode gerar tráfego de rede e revelar informações sobre sistemas. Utilize este projeto somente em:

- sistemas de sua propriedade;
- laboratórios intencionalmente vulneráveis;
- ambientes CTF em que os testes sejam permitidos;
- ambientes para os quais você possua autorização explícita.

O projeto é destinado a educação em cybersecurity, desenvolvimento de portfólio e fluxos autorizados de avaliação de segurança.

## Autor

**Murayama**

Projeto de portfólio em Cybersecurity / AppSec.
