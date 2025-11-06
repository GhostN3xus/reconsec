#!/usr/bin/env bash
set -euo pipefail
TARGET="$1"
PAYLOAD="$2"

# Simula uma verificação de vulnerabilidade. Se o payload for um valor específico,
# imprime um indicador de sucesso. Em um cenário real, esta lógica seria
# mais complexa (por exemplo, verificando por um prompt de shell, etc.).
if [[ "$PAYLOAD" == "__TEST_VULN__" ]]; then
    echo "VULNERABLE: Test payload executed successfully."
    # Não executa o curl para o payload de teste
    exit 0
fi

# O padrão executa com rede desabilitada para segurança. Para testes reais,
# a rede precisaria ser configurada adequadamente.
docker run --rm --network none curlimages/curl:8.2.1 -sS -X GET --path-as-is "$TARGET?p=$PAYLOAD" || true
