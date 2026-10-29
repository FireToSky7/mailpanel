#!/bin/bash
# =============================================================================
# Бэкап iRedMail 1.7.4 + MailPanel
#
# Что сохраняет:
#   - SQL: vmail, amavisd, iredapd, roundcubemail, mailpanel (+ sogo если есть)
#   - письма: /var/vmail
#   - конфиги: postfix, dovecot, amavis, iredapd, nginx, ssl, fail2ban, opendkim
#   - MailPanel: /opt/mailpanel + /etc/mailpanel
#
# Запуск на ПРОДЕ (от root):
#   sudo bash /opt/mailpanel/scripts/mailpanel-backup.sh
#   sudo bash /opt/mailpanel/scripts/mailpanel-backup.sh /mnt/nas/mail-backups
#
# Cron (ежедневно в 2:30):
#   30 2 * * * root /opt/mailpanel/scripts/mailpanel-backup.sh >>/var/log/mailpanel-backup.log 2>&1
#
# Пароль MySQL root (по приоритету):
#   1) переменная MYSQL_ROOT_PASSWORD
#   2) файл /root/.my.cnf
#   3) socket-auth без пароля
# =============================================================================
set -euo pipefail

BACKUP_ROOT="${1:-/var/backups/mailpanel}"
KEEP_DAYS="${MAILPANEL_BACKUP_KEEP_DAYS:-14}"
STAMP="$(date +%Y%m%d_%H%M%S)"
DEST="${BACKUP_ROOT}/${STAMP}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Запускайте от root: sudo bash $0"
  exit 1
fi

mkdir -p "$DEST"/{sql,configs,vmail,meta}
echo "==> Бэкап в $DEST"

mysql_args=()
if [[ -n "${MYSQL_ROOT_PASSWORD:-}" ]]; then
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  mysql_args+=(-uroot)
elif [[ -f /root/.my.cnf ]]; then
  mysql_args+=(--defaults-extra-file=/root/.my.cnf)
else
  mysql_args+=(-uroot)
fi

dump_db() {
  local db="$1"
  if mysql "${mysql_args[@]}" -Nse "SHOW DATABASES LIKE '${db}'" 2>/dev/null | grep -qx "$db"; then
    echo "  SQL: $db"
    mysqldump "${mysql_args[@]}" \
      --single-transaction --routines --triggers --events \
      --default-character-set=utf8mb4 \
      "$db" | gzip -c >"${DEST}/sql/${db}.sql.gz"
  else
    echo "  SQL: $db — нет, пропуск"
  fi
}

echo "==> Дампы БД"
for db in vmail amavisd iredapd roundcubemail mailpanel sogo; do
  dump_db "$db"
done

echo "==> Конфиги"
TAR_LIST=()
add_path() {
  local p="$1"
  if [[ -e "$p" ]]; then
    echo "  + $p"
    TAR_LIST+=("${p#/}")
  fi
}

add_path /etc/iredmail-release
add_path /etc/postfix
add_path /etc/dovecot
add_path /etc/amavisd
add_path /etc/mail/spamassassin
add_path /etc/nginx
add_path /etc/fail2ban
add_path /etc/opendkim
add_path /etc/pki/tls
add_path /etc/letsencrypt
add_path /opt/iredapd
add_path /opt/mailpanel
add_path /etc/mailpanel
add_path /var/lib/dkim
add_path /root/iRedMail.tips

if [[ ${#TAR_LIST[@]} -gt 0 ]]; then
  tar -C / -czf "${DEST}/configs/configs.tar.gz" "${TAR_LIST[@]}"
fi

echo "==> Почта /var/vmail (самый долгий шаг)"
if [[ -d /var/vmail ]]; then
  tar -C / -czf "${DEST}/vmail/vmail.tar.gz" \
    --exclude='var/vmail/*/Maildir/dovecot.index*' \
    var/vmail
else
  echo "  ОШИБКА: /var/vmail не найден"
  exit 1
fi

echo "==> Метаданные"
{
  echo "stamp=$STAMP"
  echo "created=$(date -Iseconds)"
  echo "iredmail_release=$(cat /etc/iredmail-release 2>/dev/null || echo unknown)"
  echo "hostname=$(hostname -f 2>/dev/null || hostname)"
  ip -4 -o addr show scope global 2>/dev/null | awk '{print "ip="$4}' | cut -d/ -f1
  echo "mailpanel=$( [[ -d /opt/mailpanel ]] && echo yes || echo no )"
} >"${DEST}/meta/info.txt"

cp -a /etc/iredmail-release "${DEST}/meta/" 2>/dev/null || true
uname -a >"${DEST}/meta/uname.txt" 2>/dev/null || true

( cd "$DEST" && find . -type f ! -name 'SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum ) \
  >"${DEST}/SHA256SUMS" || true

touch "${DEST}/COMPLETE"

echo "==> Ротация: старше ${KEEP_DAYS} дн. в ${BACKUP_ROOT}"
find "$BACKUP_ROOT" -mindepth 1 -maxdepth 1 -type d ! -name "$STAMP" -mtime "+${KEEP_DAYS}" \
  -exec rm -rf {} + 2>/dev/null || true

SIZE="$(du -sh "$DEST" | awk '{print $1}')"
echo ""
echo "Готово: $DEST  ($SIZE)"
echo "Восстановление:"
echo "  sudo bash /opt/mailpanel/scripts/mailpanel-restore.sh $DEST"
