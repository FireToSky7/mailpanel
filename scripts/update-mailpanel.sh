#!/bin/bash
# Обновление MailPanel после git pull (код + сборка frontend + перезапуск)
set -euo pipefail

INSTALL_DIR="${1:-/opt/mailpanel}"

if [ ! -d "$INSTALL_DIR" ]; then
  echo "ОШИБКА: каталог $INSTALL_DIR не найден"
  exit 1
fi

cd "$INSTALL_DIR"

echo "==> git pull"
git pull origin main

echo "==> Сборка frontend"
cd "$INSTALL_DIR/frontend"
if [ ! -d node_modules ]; then
  npm install
fi
npm run build

if [ ! -f "$INSTALL_DIR/frontend/dist/index.html" ]; then
  echo "ОШИБКА: frontend/dist не собран"
  exit 1
fi

echo "==> Перезапуск mailpanel"
systemctl restart mailpanel
sleep 1
systemctl is-active --quiet mailpanel

echo ""
echo "Готово. Проверка:"
echo "  curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/"
echo "  ls -la $INSTALL_DIR/frontend/dist/assets/ | head"
