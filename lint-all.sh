#!/bin/bash

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

CONFIG_PATH=".golangci.yml"

echo -e "${NC}0_W_0 Проверка кода...${NC}"

MODULE_DIRS=$(find . -mindepth 2 -name "go.mod" -exec dirname {} \;)

allModules=0

if [[ ! -f "$CONFIG_PATH" ]]; then
  echo -e "${RED}Конфиг $CONFIG_PATH не найден!${NC}"
  exit 1
fi

for dir in $MODULE_DIRS; do
  if [[ -d "$dir" ]]; then
    allModules=$((allModules + 1))
    echo -e "${NC}Проверка модуля: $dir${NC}"
    pushd "$dir" > /dev/null
    golangci-lint run --config="/$CONFIG_PATH" ./...
    echo -e "${GREEN}Проверка успешна: $dir${NC}"
    echo ""
    popd > /dev/null
  fi
done

echo -e "${GREEN}Все $allModules модуля прошли проверку без ошибок!${NC}"
