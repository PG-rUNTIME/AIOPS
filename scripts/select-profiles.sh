#!/usr/bin/env bash
# LLM selection for `make up`: vLLM if a GPU is present, otherwise a hosted API if
# .env points at one with a key, otherwise a small local model via Ollama.
set -euo pipefail
profiles="core,observability"
base=$(grep -E '^AIOPS_LLM__BASE_URL=' .env | cut -d= -f2- || true)
key=$(grep -E '^AIOPS_LLM__API_KEY=' .env | cut -d= -f2- || true)
if command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1 && [[ $base == *vllm* ]]; then
  profiles="$profiles,ai-gpu"
elif [[ -n "$key" && $base != *ollama* && $base != *vllm* ]]; then
  :  # hosted API: no local model container
else
  profiles="$profiles,ai"
fi
[[ -n "${EXTRA_PROFILES:-}" ]] && profiles="$profiles,$EXTRA_PROFILES"
echo "$profiles"
