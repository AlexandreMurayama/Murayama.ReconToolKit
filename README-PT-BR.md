# Murayama Recon Automation Toolkit

[English](README.md) \| [Português (Brasil)](README-PT-BR.md)

Toolkit modular de reconhecimento desenvolvido em Python para avaliações
de segurança autorizadas, laboratórios de cybersecurity e uso
educacional.

O projeto combina **componentes nativos de reconhecimento implementados
em Python** com integrações opcionais de ferramentas consolidadas. O
objetivo não é substituir ferramentas como Nmap ou Subfinder, mas
demonstrar como diferentes etapas de reconhecimento podem ser
automatizadas, validadas, correlacionadas e exportadas em um único
fluxo.

> **Somente para uso autorizado.** Execute este toolkit apenas contra
> sistemas de sua propriedade ou para os quais você possua autorização
> explícita para realizar testes de segurança.

## Funcionalidades

### Componentes nativos

-   Enumeração DNS (`A`, `AAAA`, `MX`, `NS`, `TXT`)
-   Enumeração concorrente de subdomínios utilizando wordlists
-   Detecção de wildcard DNS
-   Resolução IPv4 e IPv6 de subdomínios
-   Scanner TCP concorrente
-   Banner grabbing nativo e concorrente de serviços
-   Probes ativos para banners HTTP e HTTPS/TLS
-   Coleta passiva de banners para serviços que se identificam após a
    conexão
-   Suporte a probing SMTP
-   Identificação de serviços comuns
-   Reconhecimento HTTP/HTTPS
-   Extração do título HTML
-   Fingerprinting básico de tecnologias
-   Security Header Analyzer com validação dos valores
-   Classificação dos headers (`GOOD`, `WEAK`, `MISSING`)
-   Severidade, problemas identificados e recomendações de correção
-   Security Score (`0-100`)
-   Análise nativa de segurança TLS/SSL
-   Inspeção do protocolo TLS e cipher suite
-   Análise de CN, SAN, emissor, validade e expiração do certificado
-   Validação de hostname e confiança da cadeia do certificado
-   Classificação dos achados TLS (`GOOD`, `WEAK`, `HIGH`, `UNKNOWN`)
-   TLS Security Score (`0-100`)
-   Suporte a porta TLS personalizada
-   Correlação e deduplicação de subdomínios
-   Geração de relatórios JSON
-   HTML Security Assessment Report
-   Executive Summary com contagem consolidada de findings
-   Security Findings consolidados com severidade, status, recomendações e ativos afetados
-   IDs determinísticos de findings (`MR-HTTP-*`, `MR-TLS-*`)
-   Logging verbose/debug
-   Testes automatizados com pytest (61 testes passando atualmente)
-   Interface de linha de comando instalável (`murayama-recon`)
-   Banner de terminal personalizado MurayamaRecon

### Enriquecimento externo

-   **Nmap** --- enriquece as portas encontradas pelo scanner nativo com
    informações de serviço/produto/versão
-   **Subfinder** --- adiciona descoberta passiva de subdomínios,
    seguida de validação DNS realizada pelo próprio toolkit

O scanner nativo continua responsável pela descoberta inicial de portas.
O Nmap é uma etapa opcional de enriquecimento. Da mesma forma,
resultados passivos do Subfinder são tratados como **candidatos**, e não
como ativos confirmados, até resolverem via DNS.

## Arquitetura

``` text
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

``` text
Murayama.ReconToolKit/
├── recon/
│   ├── __init__.py
│   ├── app.py
│   ├── banner.py
│   ├── banner_grabber.py
│   ├── cli.py
│   ├── cli_entry.py
│   ├── dns.py
│   ├── http.py
│   ├── logger.py
│   ├── nmap.py
│   ├── output.py
│   ├── report.py
│   ├── security_headers.py
│   ├── ports.py
│   ├── subdomains.py
│   ├── subfinder.py
│   ├── technologies.py
│   └── tls.py
├── tests/
├── wordlists/
│   └── subdomains.txt
├── output/
│   └── .gitkeep
├── pyproject.toml
├── requirements.txt
├── pytest.ini
├── README.md
└── README-PT-BR.md
```

## Requisitos

-   Python 3
-   pip
-   Nmap (opcional, necessário apenas para `--nmap`)
-   Subfinder (opcional, necessário apenas para `--subfinder`)

O toolkit foi desenvolvido e testado no Windows. As ferramentas externas
precisam estar disponíveis no `PATH` do sistema.

Verifique as instalações:

``` bash
python --version
nmap --version
subfinder --version
```

## Instalação

Clone o repositório e entre no diretório do projeto:

``` bash
git clone <repository-url>
cd Murayama.ReconToolKit
```

Crie um ambiente virtual:

``` bash
python -m venv .venv
```

Ative no Windows usando Git Bash:

``` bash
source .venv/Scripts/activate
```

No Prompt de Comando:

``` cmd
.venv\Scripts\activate
```

No PowerShell:

``` powershell
.venv\Scripts\Activate.ps1
```

No Linux/macOS:

``` bash
source .venv/bin/activate
```

Instale as dependências Python:

``` bash
python -m pip install -r requirements.txt
```

Instale o toolkit como uma CLI Python em modo editável:

``` bash
python -m pip install -e .
```

Depois da instalação, ele pode ser executado diretamente pelo terminal:

``` bash
murayama-recon --help
```

A instalação editável é especialmente útil durante o desenvolvimento,
pois alterações feitas no código-fonte passam a ser utilizadas pela CLI
sem a necessidade de reinstalar o pacote.

## Interface de linha de comando

O projeto agora funciona como uma ferramenta de linha de comando. **Não
é necessário utilizar PyCharm** ou outra IDE para executá-lo após a
instalação.

Sintaxe geral:

``` bash
murayama-recon ALVO [OPÇÕES]
```

Para visualizar todas as opções:

``` bash
murayama-recon --help
```

O toolkit atualmente oferece:

``` text
--dns                 Executa enumeração DNS
--subdomains          Executa enumeração nativa de subdomínios
--subfinder           Executa descoberta passiva com Subfinder
--ports               Executa scanner TCP nativo
--banners             Coleta banners das portas abertas descobertas
--http                Executa reconhecimento HTTP
--tls                 Executa análise de segurança TLS/SSL
--tls-port PORT       Define uma porta TLS personalizada (padrão: 443)
--wordlist PATH       Define a wordlist de subdomínios
--threads NUMBER      Define o número de threads concorrentes
--timeout SECONDS     Define o timeout de rede
--port PORT           Verifica uma única porta TCP
--port-range RANGE    Verifica um intervalo de portas TCP
--nmap                Enriquece as portas encontradas com Nmap
--output FILE         Salva os resultados em JSON
--report FILE         Gera um relatório HTML de security assessment
--verbose             Habilita logging verbose/debug
```

Use `murayama-recon --help` como referência definitiva para a versão do
código que estiver utilizando.

## Banner de inicialização

Ao iniciar uma execução, o toolkit apresenta o banner personalizado
**MurayamaRecon**, acompanhado da versão do toolkit e do aviso de uso
exclusivo para testes autorizados.

O banner fica separado da lógica de reconhecimento, mantendo a
apresentação independente dos módulos funcionais da ferramenta.

## Exemplos de uso

### Enumeração DNS

``` bash
murayama-recon example.com --dns
```

### Enumeração nativa de subdomínios

``` bash
murayama-recon example.com --subdomains
```

Com wordlist e parâmetros personalizados:

``` bash
murayama-recon example.com \
  --subdomains \
  --wordlist wordlists/subdomains.txt \
  --threads 20 \
  --timeout 1
```

### Descoberta passiva com Subfinder

``` bash
murayama-recon example.com \
  --subfinder \
  --threads 20 \
  --timeout 1
```

Os resultados do Subfinder são inicialmente tratados como candidatos
passivos e depois validados por DNS. Isso evita que registros históricos
ou desatualizados sejam automaticamente apresentados como ativos
confirmados.

Durante o desenvolvimento, uma execução contra `example.com` demonstrou
claramente essa diferença:

``` text
[+] Passive Subdomain Discovery (Subfinder)
    Candidates discovered: 24948
    DNS validated: 1
    www.example.com -> ...
```

Os resultados das fontes passivas mudam ao longo do tempo, portanto
essas quantidades são apenas um exemplo.

### Descoberta consolidada de subdomínios

Execute os mecanismos nativo e passivo:

``` bash
murayama-recon example.com \
  --subdomains \
  --subfinder \
  --threads 20 \
  --timeout 1
```

O toolkit deduplica os hosts e registra quais mecanismos encontraram
cada ativo:

``` text
[+] Consolidated Subdomain Results
    www.example.com -> ...
        Sources: native, subfinder
```

### Scanner TCP nativo

Portas comuns:

``` bash
murayama-recon localhost --ports
```

Uma porta específica:

``` bash
murayama-recon localhost --ports --port 8080
```

Intervalo de portas:

``` bash
murayama-recon localhost --ports --port-range 1-1024
```

O toolkit não está limitado ao `localhost`. Ele pode operar contra hosts
e domínios remotos quando houver autorização para o teste.

### Banner grabbing nativo

O banner grabbing é executado depois que o scanner nativo identifica
portas TCP abertas:

``` bash
murayama-recon localhost --ports --banners
```

O módulo utiliza workers concorrentes e combina técnicas passivas e
ativas. Serviços como SSH e FTP podem se identificar imediatamente após
a conexão, enquanto serviços HTTP recebem um probe ativo. HTTPS nas
portas TLS convencionais realiza primeiro o handshake TLS e depois o
probe HTTP, e portas SMTP possuem suporte a probing específico do
protocolo.

Exemplo:

``` text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Banner Grabbing
    8080/tcp
        HTTP/1.1 404 Not Found
        Connection: close
        Server: Kestrel
```

Uma resposta `404 Not Found` ainda é uma evidência útil de
reconhecimento: confirma que um serviço HTTP respondeu e pode revelar
headers de identificação, como `Server`.

O banner grabbing e o enriquecimento com Nmap são complementares. O
módulo nativo demonstra interação direta com sockets/protocolos,
enquanto o Nmap oferece fingerprinting mais aprofundado.

### Enriquecimento com Nmap

``` bash
murayama-recon localhost --ports --nmap
```

A separação é proposital:

``` text
Scanner nativo
      |
      v
Portas abertas
      |
      v
Enriquecimento Nmap
```

Exemplo:

``` text
[+] Port Scan
    8080/tcp open (http-alt)

[+] Nmap Service Enrichment
    8080/tcp http
        Microsoft Kestrel httpd
```

Assim, o scanner desenvolvido no projeto continua responsável pela
descoberta, enquanto o Nmap complementa o resultado com fingerprinting
mais profundo.

### Reconhecimento HTTP

``` bash
murayama-recon example.com --http
```

Com descoberta prévia de portas:

``` bash
murayama-recon example.com --ports --http
```

A etapa HTTP pode coletar:

``` text
URL
Status HTTP
Server
Content-Type
Título HTML
Tecnologias identificadas
Security headers
```

### Security Header Analyzer

A etapa de reconhecimento HTTP inclui um Security Header Analyzer
nativo. Ele verifica tanto a presença de headers selecionados quanto,
quando suportado, se os valores seguem expectativas defensivas básicas.

Headers atualmente analisados:

-   `Strict-Transport-Security`
-   `Content-Security-Policy`
-   `X-Frame-Options`
-   `X-Content-Type-Options`
-   `Referrer-Policy`
-   `Permissions-Policy`

Cada header recebe uma classificação:

-   `GOOD` --- presente e aceito pelas regras atuais de validação
-   `WEAK` --- presente, mas com valor potencialmente fraco ou
    inesperado
-   `MISSING` --- ausente na resposta analisada

As verificações atuais incluem `max-age` no HSTS, `X-Frame-Options`
(`DENY` ou `SAMEORIGIN`), `X-Content-Type-Options` (`nosniff`) e
detecção em CSP de `'unsafe-inline'`, `'unsafe-eval'` e fontes wildcard.

Headers fracos ou ausentes incluem metadados de severidade, problemas
identificados e uma recomendação de correção. O toolkit também calcula
um Security Score simples de `0` a `100`:

``` text
GOOD    = 100% dos pontos
WEAK    =  50% dos pontos
MISSING =   0% dos pontos
```

Exemplo:

``` text
[+] HTTP Reconnaissance

    Security Header Analysis:

        [WEAK] Content-Security-Policy
            Value: default-src * 'unsafe-inline'
            Severity: medium
            Issues:
                - unsafe-inline directive detected.
                - Wildcard source detected.

        [GOOD] X-Frame-Options
            Value: SAMEORIGIN

    Security Score:
        Score:   25/100
        Good:    1
        Weak:    1
        Missing: 4
```

O score serve como apoio ao reconhecimento; ele não é uma classificação
de vulnerabilidade nem substitui análise manual de segurança. A
relevância e o impacto dos headers dependem da aplicação, comportamento
dos navegadores, arquitetura de implantação e demais controles.

### TLS/SSL Security Analyzer

O toolkit inclui uma etapa nativa de análise TLS/SSL para inspecionar as
características de segurança de um serviço com TLS:

``` bash
murayama-recon example.com --tls
```

Por padrão, o analyzer conecta à porta TCP `443`. Uma porta TLS
diferente pode ser definida com `--tls-port`:

``` bash
murayama-recon localhost --tls --tls-port 9443
```

Atualmente, o TLS Analyzer coleta e avalia:

-   protocolo TLS negociado
-   cipher suite negociada e tamanho da chave
-   Common Name (CN) do certificado
-   Subject Alternative Names (SANs)
-   emissor do certificado
-   período de validade e tempo restante
-   estado de expiração do certificado
-   validação do hostname
-   validação de confiança/cadeia do certificado

As verificações são apresentadas separadamente para evitar que
propriedades diferentes do certificado sejam confundidas:

``` text
Certificate -> validade temporal e expiração
Hostname    -> se o certificado corresponde ao alvo solicitado
Trust       -> se a cadeia do certificado é confiável
```

Cada verificação pode ser classificada como `GOOD`, `WEAK`, `HIGH` ou
`UNKNOWN`, incluindo severidade, problemas encontrados e recomendação de
correção quando aplicável. O analyzer também calcula um TLS Security
Score de `0` a `100`.

Exemplo contra um endpoint TLS público válido:

``` text
[+] TLS/SSL Analysis
    Protocol:       TLSv1.3
    Cipher:         TLS_AES_256_GCM_SHA384
    Cipher Bits:    256
    Common Name:    example.com

    TLS Security Analysis:

        [GOOD] Protocol
        [GOOD] Cipher
        [GOOD] Certificate
        [GOOD] Hostname
        [GOOD] Trust

    TLS Security Score:
        Score:   100/100
        Good:    5
        Weak:    0
        High:    0
        Unknown: 0
```

Durante o desenvolvimento, o analyzer também foi validado contra um
certificado self-signed local na porta `9443`. O certificado
correspondia a `localhost`, mas falhou na validação de confiança,
permitindo ao toolkit distinguir corretamente a validade do hostname da
confiança na CA:

``` text
[WEAK] Certificate
    Severity: medium
    Issues:
        - Certificate expires in 29 days.

[GOOD] Hostname

[HIGH] Trust
    Severity: high
    Issues:
        - Certificate trust validation failed: self-signed certificate

TLS Security Score:
    Score: 70/100
```

O TLS Security Score serve como apoio ao reconhecimento e não substitui
uma auditoria completa da configuração TLS. Ele representa as
verificações implementadas na versão atual do toolkit.

O reconhecimento HTTP e a análise TLS podem ser combinados e exportados
em um único relatório:

``` bash
murayama-recon example.com \
  --http \
  --tls \
  --output output/example.com.json
```

### Saída JSON

``` bash
murayama-recon example.com \
  --dns \
  --subdomains \
  --ports \
  --http \
  --output output/example.com.json
```

O relatório contém metadados e os resultados das etapas habilitadas,
incluindo a consolidação de subdomínios quando aplicável.

Estrutura resumida:

``` json
{
  "tool": "Murayama Recon Automation Toolkit",
  "version": "0.1.0",
  "target": "example.com",
  "dns": {},
  "subdomains": [],
  "subfinder": [],
  "discovered_subdomains": [],
  "ports": [],
  "banners": [],
  "nmap": [],
  "http": [],
  "tls": []
}
```


### HTML Security Assessment Report

O toolkit pode gerar um relatório HTML standalone de security assessment,
além da saída JSON:

``` bash
murayama-recon example.com \
  --http \
  --tls \
  --report output/example.com.html
```

JSON e HTML podem ser gerados na mesma execução:

``` bash
murayama-recon example.com \
  --dns \
  --subdomains \
  --ports \
  --banners \
  --http \
  --tls \
  --nmap \
  --output output/full-scan.json \
  --report output/full-scan.html
```

O relatório HTML foi projetado como uma visão orientada a assessment da mesma
estrutura `recon_results` utilizada pelo toolkit. Atualmente ele inclui:

-   alvo, timestamp de geração e metadados da ferramenta
-   Executive Summary
-   contagem consolidada de High, Medium, Low, Informational e checks aprovados
-   tabela consolidada de Security Findings
-   IDs determinísticos como `MR-HTTP-001` e `MR-TLS-001`
-   consolidação de ativos afetados para findings repetidos
-   badges visuais de severidade e status
-   recomendações de correção
-   reconhecimento DNS
-   subdomínios descobertos
-   portas abertas
-   banners de serviços coletados
-   resultados de enriquecimento Nmap quando disponíveis
-   resultados e score do HTTP Security Header Analyzer
-   resultados e score do TLS/SSL Security Analyzer

Findings HTTP repetidos encontrados tanto em HTTP quanto em HTTPS são
consolidados no Executive Summary e na seção Security Findings, evitando
inflar artificialmente a contagem. As seções técnicas continuam preservando
as evidências por endpoint.

Fluxo resumido do relatório:

``` text
MurayamaRecon Security Report
        |
        v
Executive Summary
        |
        v
Security Findings
        |
        +--> MR-HTTP-001
        +--> MR-HTTP-002
        +--> MR-TLS-001
        |
        v
Reconhecimento Técnico
        |
        +--> DNS
        +--> Subdomínios
        +--> Portas
        +--> Banners
        +--> Nmap
        |
        v
Análise de Segurança
        |
        +--> HTTP Security Headers
        +--> TLS/SSL
```

Todos os valores coletados externamente são escapados antes de serem gravados
no HTML, reduzindo o risco de injeção de conteúdo no relatório.

### Logging verbose

``` bash
murayama-recon example.com --ports --http --verbose
```

O modo verbose apresenta informações adicionais úteis para
desenvolvimento e troubleshooting.

## Testes automatizados

Execute:

``` bash
python -m pytest -v
```

A suíte atual cobre parsing de portas da CLI, comportamento do scanner,
extração de títulos HTTP, análise de tecnologias/security headers e
geração de JSON. A análise TLS/SSL também faz parte das funcionalidades
atuais.

## Decisões de arquitetura

### Scanner nativo + Banner Grabber + Nmap

O toolkit separa três camadas de reconhecimento:

``` text
Scanner TCP nativo
        |
        v
   Portas abertas
     /       \
    v         v
Banner       Nmap
Grabber      Enrichment
nativo
```

O Banner Grabber nativo interage diretamente com os serviços descobertos
usando sockets e probes específicos de protocolo. O Nmap permanece
opcional e fornece fingerprinting mais avançado de serviço/produto.
Assim, os dois mecanismos são complementares e não redundantes.

O projeto mantém um scanner TCP concorrente próprio em vez de delegar
toda a descoberta ao Nmap. Isso demonstra programação com sockets e
concorrência, enquanto permite que o Nmap seja utilizado para aquilo em
que é especialmente forte: fingerprinting mais detalhado de serviços.

### Enumeração nativa + Subfinder

A enumeração DNS baseada em wordlist e a descoberta passiva oferecem
perspectivas diferentes. O Subfinder amplia a cobertura passiva,
enquanto o toolkit valida os candidatos por DNS antes de considerá-los
confirmados.

### Correlação em vez de resultados duplicados

Quando um host é encontrado por mais de um mecanismo, o toolkit o
consolida e preserva as fontes:

``` json
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

### CLI instalável

O toolkit é empacotado através do `pyproject.toml` e disponibiliza o
comando `murayama-recon`. Isso separa o uso normal da ferramenta da
estrutura interna dos módulos Python e faz com que o projeto se comporte
como uma ferramenta convencional de linha de comando.

## Roadmap

Possíveis evoluções:

-   Novas fontes passivas de reconhecimento
-   Perfis configuráveis de portas
-   Novos probes de banner específicos por protocolo
-   Fingerprinting de serviços mais avançado
-   Análise da cadeia de redirects HTTP
-   Novas assinaturas de tecnologias
-   Relatórios CSV
-   Expansão dos testes automatizados
-   CI com verificações de segurança e qualidade

## Uso ético

Reconhecimento pode gerar tráfego de rede e revelar informações sobre
sistemas. Utilize este projeto somente em:

-   sistemas de sua propriedade;
-   laboratórios intencionalmente vulneráveis;
-   ambientes CTF em que os testes sejam permitidos;
-   ambientes para os quais você possua autorização explícita.

O projeto é destinado a educação em cybersecurity, desenvolvimento de
portfólio e fluxos autorizados de avaliação de segurança.

## Autor

**Murayama**

Projeto de portfólio em Cybersecurity / AppSec.
