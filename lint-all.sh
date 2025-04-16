#!/bin/bash

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

CONFIG_PATH=".golangci.yml"

echo -e "${GREEN}Проверка кода...${NC}"


if golangci-lint run --config="$CONFIG_PATH" ./...; then
  echo -e "${GREEN}Линтинг успешен"
else
  echo -e "${RED}Найдены проблемы"
fi