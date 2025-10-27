# ReconSec

ReconSec é um conjunto de utilitários de segurança ofensiva que demonstra fluxos de reconhecimento,
provas de conceito seguras e automação de varreduras ativas, estáticas e dinâmicas. O projeto expõe
uma CLI Go única (`reconsec`) com subcomandos focados em experimentação controlada, mantendo uma
camada de relatório unificada (`pkg/report`).

## Sumário
- [Principais funcionalidades](#principais-funcionalidades)
- [Instalação](#instalação)
- [Uso rápido](#uso-rápido)
- [Subcomandos e argumentos](#subcomandos-e-argumentos)
  - [`version`](#version)
  - [`recon`](#recon)
  - [`activescan`](#activescan)
  - [`proxy`](#proxy)
  - [`sast-scan`](#sast-scan)
  - [`test`](#test)
- [Payloads e sandbox](#payloads-e-sandbox)
- [Estrutura do projeto](#estrutura-do-projeto)

## Principais funcionalidades
- **Varredura ativa controlada**: executa payloads pré-aprovados em um alvo utilizando uma sandbox
  reforçada antes de enviar qualquer tráfego direto. Inclui validações obrigatórias de autorização
  e isolamento para reduzir riscos.【F:pkg/active/active.go†L13-L58】
- **Proxy DAST simples**: proxy HTTP(s) em modo transparente que registra requisições e respostas para
  inspeção manual, incluindo suporte a túneis CONNECT e limite configurável de corpo de mensagem.【F:pkg/dast/proxy.go†L15-L98】
- **Motor SAST baseado em regras**: carrega regras em JSON e varre diretórios suportando diversas
  linguagens, gerando achados normalizados em um formato comum de relatório.【F:pkg/sast/engine.go†L13-L86】
- **Prova de conceito segura**: sonda endpoints com um token de marcação, identifica reflexão e
  responde com severidade/nível de confiança adequados sem executar payloads perigosos.【F:pkg/poc/poc.go†L13-L55】

## Instalação
1. **Pré-requisitos**: Go 1.21 ou superior (veja `go.mod`).【F:go.mod†L1-L4】
2. **Clone o repositório**:
   ```bash
   git clone https://github.com/ghostn3xus/reconsec.git
   cd reconsec
   ```
3. **Compile o binário**:
   ```bash
   go build -o bin/reconsec ./cmd/reconsec
   ```

> Para atualizar dependências, utilize `go mod tidy`. Nenhum componente externo adicional é
> instalado pelo projeto por padrão.

## Uso rápido
Execute o binário compilado ou utilize `go run` diretamente:
```bash
go run ./cmd/reconsec --help  # exibirá a mensagem de uso padrão
./bin/reconsec version       # mostra versão com timestamp
```

## Subcomandos e argumentos
Cada subcomando possui opções específicas. Em caso de argumentos inválidos, a CLI exibe uma mensagem
resumindo os comandos disponíveis (`usage`).【F:cmd/reconsec/main.go†L20-L70】

### `version`
- **Função**: imprime a versão com timestamp RFC3339 da execução atual.【F:cmd/reconsec/main.go†L23-L26】
- **Uso**:
  ```bash
  reconsec version
  ```

### `recon`
- **Função**: placeholder demonstrativo que informa sobre a necessidade de subcomandos adicionais
  numa versão completa. Útil para verificar o empacotamento básico da CLI.【F:cmd/reconsec/main.go†L27-L30】

### `activescan`
- **Função**: executa payloads aprovados em um alvo dentro de uma sandbox, retornando achados no
  formato JSON.
- **Argumentos**:
  | Flag | Descrição | Padrão |
  |------|-----------|--------|
  | `-url <alvo>` | URL alvo obrigatória para varredura. | vazio |
  | `-payloads <caminho>` | Caminho para arquivo JSON de payloads aprovados. | `payloads/approved.json` |
  | `--sandbox true` | Deve ser `true` para permitir execução (fail-safe). | `false` |
  | `--confirm-authorized <texto>` | Declaração explícita de autorização para executar o teste. | vazio |
- **Notas**:
  - Se `--confirm-authorized` não for fornecido **ou** `--sandbox true` não estiver definido, o
    comando aborta com erro para evitar uso indevido.【F:pkg/active/active.go†L31-L45】
  - O resultado é impresso em JSON identado (`[]report.Finding`).【F:cmd/reconsec/main.go†L33-L43】

### `proxy`
- **Função**: inicia um proxy HTTP/HTTPS simples em `:8081`, registrando tráfego em
  `/tmp/recon-proxy.log`. Encerre com `Ctrl+C`.
- **Notas**:
  - O proxy grava logs tanto na saída padrão quanto no arquivo especificado.【F:pkg/dast/proxy.go†L23-L32】
  - O corpo das requisições/respostas é truncado para `MaxBody` bytes (padrão: `200000`).【F:pkg/dast/proxy.go†L15-L91】
- **Uso**:
  ```bash
  reconsec proxy
  ```

### `sast-scan`
- **Função**: roda análise estática sobre um diretório.
- **Sintaxe**:
  ```bash
  reconsec sast-scan [caminho]
  ```
- **Argumentos**:
  | Parâmetro | Descrição | Padrão |
  |-----------|-----------|--------|
  | `caminho` | Diretório raiz a ser inspecionado. | `.` |
- **Notas**:
  - As regras são carregadas de `pkg/sast/rules.json`. Ajuste ou adicione regras conforme necessário.【F:cmd/reconsec/main.go†L44-L55】【F:pkg/sast/engine.go†L25-L38】
  - Saída em JSON no formato `[]report.Finding`.

### `test`
- **Função**: executa uma prova de conceito (PoC) segura para avaliar reflexão de parâmetros.
- **Sintaxe**:
  ```bash
  reconsec test <url>
  ```
- **Notas**:
  - Define automaticamente o parâmetro `reconsec_probe` com token `__RECONSEC_TEST__` para verificar
    reflexão e códigos de status.【F:cmd/reconsec/main.go†L56-L67】【F:pkg/poc/poc.go†L17-L54】
  - A saída é um único objeto `report.Finding` em JSON.

## Payloads e sandbox
- Os payloads usados em `activescan` ficam em `payloads/approved.json`. Cada entrada possui nome,
  categoria e template com marcador `{{INJECT}}` substituído por um token único em tempo de execução.
  Ajuste o arquivo para adicionar payloads autorizados.【F:payloads/approved.json†L1-L12】
- A sandbox de referência executa `scripts/run_payload_in_sandbox.sh`, que por padrão usa um container
  Docker com rede desativada. Configure esse script para refletir seu ambiente real. Há um lembrete
  adicional em `scripts/README_SANDBOX.md`.【F:pkg/active/active.go†L39-L46】【F:scripts/README_SANDBOX.md†L1-L1】

## Estrutura do projeto
```
cmd/reconsec/        # Ponto de entrada da CLI
internal/            # Componentes internos e CLI helpers
pkg/active           # Scanner ativo e carregamento de payloads
pkg/dast             # Proxy HTTP de inspeção
pkg/poc              # Provas de conceito seguras
pkg/report           # Tipos compartilhados de relatório/achados
pkg/sast             # Motor SAST baseado em regras JSON
scripts/             # Script de sandbox e documentação
payloads/            # Payloads aprovados para execuções seguras
```

Sinta-se livre para estender os pacotes ou integrar as saídas JSON com pipelines de segurança
existentes.
