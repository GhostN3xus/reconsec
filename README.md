# ReconSec

ReconSec é uma ferramenta de linha de comando de nível profissional, escrita em Go, focada em **reconhecimento profundo e análise dinâmica** de aplicações web. Inspirada em ferramentas como `amass`, `subfinder` e `dirsearch`, a ReconSec utiliza técnicas avançadas para fornecer resultados abrangentes e precisos.

## Sumário
- [Principais funcionalidades](#principais-funcionalidades)
- [Instalação](#instalação)
- [Uso rápido](#uso-rápido)
- [Comandos](#comandos)
  - [`recon`](#recon)
  - [`dirscan`](#dirscan)
  - [`activescan`](#activescan)
  - [`test`](#test)
  - [`proxy`](#proxy)
  - [`version`](#version)
- [Sistema de Payloads](#sistema-de-payloads)
- [Estrutura do projeto](#estrutura-do-projeto)

## Principais funcionalidades
- **Enumeração Avançada de Subdomínios**: Descubra subdomínios usando um método de duas fases que combina enumeração por lista de palavras com **geração de permutações**, aumentando significativamente a cobertura.
- **Varredura Profunda de Diretórios**: Utiliza o poder do motor **dirsearch**, o padrão da indústria, para realizar varreduras recursivas e profundas em servidores web.
- **Varredura Ativa Flexível**: Execute payloads de segurança a partir de um diretório de arquivos JSON, permitindo uma fácil organização e expansão.
- **Análise de Reflexão Inteligente**: Teste a reflexão de parâmetros com análise sensível ao contexto para identificar vulnerabilidades de XSS com maior precisão e menos falsos positivos.
- **Proxy de Análise Passiva**: Intercepte o tráfego HTTP para análise passiva, como a detecção de cabeçalhos de segurança ausentes.

## Instalação
1. **Pré-requisitos**:
   - Go 1.21 ou superior.
   - **dirsearch**: O comando `dirscan` requer que o `dirsearch` esteja instalado e no seu `PATH`. Instale-o com:
     ```bash
     pip3 install dirsearch
     ```
2. **Clone o repositório**:
   ```bash
   git clone https://github.com/ghostn3xus/reconsec.git
   cd reconsec
   ```
3. **Compile o binário**:
   ```bash
   go build -o bin/reconsec ./cmd/reconsec
   ```

## Uso rápido
```bash
# Exibir a ajuda geral
go run ./cmd/reconsec --help

# Executar uma enumeração de subdomínios de duas fases
go run ./cmd/reconsec recon example.com

# Executar uma varredura de diretórios profunda com o motor dirsearch
go run ./cmd/reconsec dirscan http://example.com
```

## Comandos

### `recon`
- **Função**: Executa uma enumeração de subdomínios de duas fases (lista de palavras + permutações).
- **Uso**: `reconsec recon [domain]`
- **Flags**:
  - `--wordlist <path>`: Caminho para uma lista de palavras customizada para a primeira fase.
  - `--threads <int>`: Número de threads a serem usadas (padrão: 10).

### `dirscan`
- **Função**: Executa uma varredura profunda e recursiva usando o motor do `dirsearch`.
- **Uso**: `reconsec dirscan [url]`
- **Nota**: Este comando requer que o `dirsearch` esteja instalado e acessível no `PATH` do sistema.

### `activescan`
- **Função**: Executa uma varredura ativa usando um conjunto de payloads.
- **Uso**: `reconsec activescan --url <target-url>`
- **Flags**:
  - `--payloads <path>`: Caminho para um diretório contendo arquivos de payload `.json` (padrão: `payloads/`).
  - `--sandbox`: Deve ser `true` para executar os payloads em um ambiente de sandbox.

### `test`
- **Função**: Executa uma sonda segura para testar a reflexão de parâmetros com análise de contexto.
- **Uso**: `reconsec test [url]`
- **Flags**:
  - `--param <name>`: Nome do parâmetro a ser usado na sonda (padrão: `reconsec_probe`).

### `proxy`
- **Função**: Inicia um proxy HTTP para análise passiva de tráfego.
- **Uso**: `reconsec proxy`
- **Flags**:
  - `--addr <address>`: Endereço para o proxy escutar (padrão: `:8081`).
  - `--log <path>`: Caminho para o arquivo de log do proxy (padrão: `/tmp/recon-proxy.log`).

### `version`
- **Função**: Imprime a versão da ferramenta.
- **Uso**: `reconsec version`

## Sistema de Payloads
O comando `activescan` carrega todos os arquivos `.json` localizados no diretório especificado pela flag `--payloads`. Isso permite que você organize seus payloads por categoria (XSS, SQLi, etc.) em arquivos separados, tornando o sistema mais modular e fácil de gerenciar.

## Estrutura do projeto
```
cmd/reconsec/        # Ponto de entrada da CLI (Cobra)
pkg/active           # Scanner ativo e carregamento de payloads
pkg/dast             # Proxy de análise passiva
pkg/discovery        # Wrapper para o motor dirsearch
pkg/poc              # Sonda de reflexão de parâmetros
pkg/recon            # Enumeração de subdomínios em duas fases
pkg/report           # Tipos de relatório compartilhados
scripts/             # Scripts de sandbox
payloads/            # Diretório de payloads
```
