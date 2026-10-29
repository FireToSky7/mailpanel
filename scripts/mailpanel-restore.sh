#!/bin/bash
# =============================================================================
# Восстановление iRedMail 1.7.4 + MailPanel из бэкапа mailpanel-backup.sh
#
# ПРЕДПОСЫЛКИ на новой ВМ (делать ДО запуска этого скрипта):
#   1. РЕД ОС той же мажорной версии
#   2. Установлен iRedMail **1.7.4** (как на проде), тот же backend (MariaDB)
#   3. Сеть: желательно ТОТ ЖЕ LAN IP, что был у старого сервера
#   4. Скопирован каталог бэкапа, например /root/restore/20261021_023000
#
# Запуск:
#   sudo bash /opt/mailpanel/scripts/mailpanel-restore.sh /path/to/20261021_023000
#
# Скрипт:
#   - останавливает почтовые службы
#   - восстанавливает SQL-дампы
#   - распаковывает /var/vmail
#   - накатывает конфиги из бэкапа
#   - запускает службы
# =============================================================================
set -euo pipefail

SRC="${1:-}"
CONFIRM="${MAILPANEL_RESTORE_CONFIRM:-}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Запускайте от root"
  exit 1
fi

if [[ -z "$SRC" || ! -d "$SRC" ]]; then
  echo "Использование: $0 /path/to/backup_dir"
  echo "Пример:       $0 /var/backups/mailpanel/20261021_023000"
  exit 1
fi

if [[ ! -f "$SRC/COMPLETE" ]]; then
  echo "ОШИБКА: в $SRC нет файла COMPLETE — бэкап неполный или повреждён"
  exit 1
fi

echo "=============================================="
echo " ВНИМАНИЕ: восстановление ПЕРЕЗАПИШЕТ"
echo "  - базы vmail/amavisd/iredapd/roundcubemail/mailpanel"
echo "  - /var/vmail"
echo "  - конфиги postfix/dovecot/amavis/iredapd/nginx/mailpanel"
echo " Источник: $SRC"
if [[ -f "$SRC/meta/info.txt" ]]; then
  echo "--- meta ---"
  cat "$SRC/meta/info.txt"
  echo "------------"
fi
echo "=============================================="

if [[ "$CONFIRM" != "YES" ]]; then
  read -r -p "Введите YES для продолжения: " ans
  if [[ "$ans" != "YES" ]]; then
    echo "Отменено"
    exit 1
  fi
fi

# Версия iRedMail
EXPECTED="$(tr -d '[:space:]' <"$SRC/meta/iredmail-release" 2>/dev/null || true)"
CURRENT="$(tr -d '[:space:]' </etc/iredmail-release 2>/dev/null || true)"
if [[ -n "$EXPECTED" && -n "$CURRENT" && "$EXPECTED" != "$CURRENT" ]]; then
  echo "ПРЕДУПРЕЖДЕНИЕ: бэкап с iRedMail $EXPECTED, на ВМ сейчас $CURRENT"
  echo "Рекомендуется одинаковая версия (у вас план: 1.7.4)."
  read -r -p "Продолжить всё равно? [y/N]: " go
  [[ "$go" == "y" || "$go" == "Y" ]] || exit 1
fi

mysql_args=()
if [[ -n "${MYSQL_ROOT_PASSWORD:-}" ]]; then
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  mysql_args+=(-uroot)
elif [[ -f /root/.my.cnf ]]; then
  mysql_args+=(--defaults-extra-file=/root/.my.cnf)
else
  mysql_args+=(-uroot)
fi

echo "==> Останавливаем службы"
for svc in mailpanel postfix dovecot amavisd iredapd nginx; do
  systemctl stop "$svc" 2>/dev/null || true
done

echo "==> Восстановление SQL"
restore_db() {
  local db="$1"
  local file="$SRC/sql/${db}.sql.gz"
  if [[ ! -f "$file" ]]; then
    echo "  $db — дампа нет, пропуск"
    return
  fi
  echo "  $db"
  mysql "${mysql_args[@]}" -e "CREATE DATABASE IF NOT EXISTS \`${db}\` DEFAULT CHARACTER SET utf8mb4"
  # не трогаем mysql.* системную БД
  gunzip -c "$file" | mysql "${mysql_args[@]}" "$db"
}

for db in vmail amavisd iredapd roundcubemail mailpanel sogo; do
  restore_db "$db"
done

echo "==> Восстановление /var/vmail"
if [[ -f "$SRC/vmail/vmail.tar.gz" ]]; then
  # сохраняем текущий на всякий случай
  if [[ -d /var/vmail ]] && [[ ! -d /var/vmail.pre-restore ]]; then
    mv /var/vmail /var/vmail.pre-restore
  else
    rm -rf /var/vmail
  fi
  tar -C / -xzf "$SRC/vmail/vmail.tar.gz"
  # права (типичные для iRedMail)
  if id vmail &>/dev/null; then
    chown -R vmail:vmail /var/vmail
  fi
else
  echo "  ОШИБКА: нет vmail.tar.gz"
  exit 1
fi

echo "==> Восстановление конфигов"
if [[ -f "$SRC/configs/configs.tar.gz" ]]; then
  # бэкап текущих конфигов перед накатом
  SAFETY="/root/pre-restore-configs-$(date +%Y%m%d_%H%M%S).tar.gz"
  tar -C / -czf "$SAFETY" \
    etc/postfix etc/dovecot etc/amavisd opt/iredapd opt/mailpanel etc/mailpanel \
    2>/dev/null || true
  echo "  Текущие конфиги сохранены в $SAFETY"
  tar -C / -xzf "$SRC/configs/configs.tar.gz"
else
  echo "  configs.tar.gz нет — пропуск (только БД и почта)"
fi

# systemd unit MailPanel
if [[ -f /opt/mailpanel/scripts/mailpanel.service ]]; then
  cp -a /opt/mailpanel/scripts/mailpanel.service /etc/systemd/system/mailpanel.service
  systemctl daemon-reload
  systemctl enable mailpanel 2>/dev/null || true
fi

echo "==> Запуск служб"
systemctl start mariadb mysqld 2>/dev/null || systemctl start mariadb 2>/dev/null || true
sleep 2
for svc in postfix dovecot amavisd iredapd nginx mailpanel; do
  systemctl start "$svc" 2>/dev/null || echo "  не удалось стартовать $svc (проверьте вручную)"
done

echo ""
echo "==> Статус"
for svc in postfix dovecot amavisd iredapd nginx mariadb mailpanel; do
  printf "  %-12s %s\n" "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo n/a)"
done

echo ""
echo "Готово. Проверьте:"
echo "  1) IP сервера = как в DNS / DNAT роутера"
echo "  2) Roundcube / Outlook логин"
echo "  3) Отправка/приём тестового письма"
echo "  4) MailPanel: http://IP:8080 или ваш proxy"
echo "  5) journalctl -u postfix -u dovecot -n 50 --no-pager"
echo ""
echo "Если MailPanel не стартует — пароли в /opt/mailpanel/config.yaml должны"
echo "совпадать с восстановленными БД (они уже из бэкапа, обычно ок)."
