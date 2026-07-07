#!/bin/bash
set -euo pipefail

# Установка MailPanel на РЕД ОС 8 с iRedMail
# Запуск: sudo bash scripts/install-redos.sh

INSTALL_DIR="/opt/mailpanel"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "==> Установка зависимостей"
dnf install -y python3 python3-pip mariadb nodejs npm || true
pip3 install -r "$SCRIPT_DIR/backend/requirements.txt"

echo "==> Копирование файлов"
mkdir -p "$INSTALL_DIR"
rsync -a --exclude node_modules --exclude frontend/dist "$SCRIPT_DIR/" "$INSTALL_DIR/"

if [ ! -f "$INSTALL_DIR/config.yaml" ]; then
  cp "$INSTALL_DIR/config.example.yaml" "$INSTALL_DIR/config.yaml"
  echo "!! Создан $INSTALL_DIR/config.yaml — настройте пароли БД и secret_key"
fi

echo "==> Инициализация БД mailpanel"
mysql -u root -p < "$INSTALL_DIR/scripts/init-db.sql"

echo "==> Сборка frontend"
cd "$INSTALL_DIR/frontend"
npm install
npm run build

echo "==> systemd"
cp "$INSTALL_DIR/scripts/mailpanel.service" /etc/systemd/system/mailpanel.service
systemctl daemon-reload
systemctl enable mailpanel
systemctl restart mailpanel

echo ""
echo "Готово. Панель: http://127.0.0.1:8080"
echo "Первый вход: admin / admin123 — СМЕНИТЕ ПАРОЛЬ СРАЗУ"
echo "Настройте Nginx reverse proxy для HTTPS."
