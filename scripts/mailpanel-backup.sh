#!/bin/bash
# =============================================================================
# Бэкап iRedMail 1.7.4 + MailPanel (для переноса на новую ВМ)
#
# Что сохраняет:
#   - SQL: vmail, amavisd, iredapd, roundcubemail, mailpanel (+ sogo)
#   - SQL-пользователи приложений (пароли + гранты) → meta/mysql-users.sql
#   - пароли из config.yaml / типичных cf → meta/app-passwords.env (chmod 600)
#   - письма: /var/vmail
#   - конфиги (без venv/node_modules/.git — их restore соберёт заново)
#   - MailPanel код + /etc/mailpanel + iRedMail.tips
#
# Запуск на ПРОДЕ (root):
#   sudo bash /opt/mailpanel/scripts/mailpanel-backup.sh
#   sudo bash /opt/mailpanel/scripts/mailpanel-backup.sh /mnt/nas/mail-backups
#
# Cron:
#   30 2 * * * root /opt/mailpanel/scripts/mailpanel-backup.sh >>/var/log/mailpanel-backup.log 2>&1
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

if ! mysql "${mysql_args[@]}" -e "SELECT 1" &>/dev/null; then
  echo "ОШИБКА: нет доступа к MySQL root. Задайте MYSQL_ROOT_PASSWORD или /root/.my.cnf"
  exit 1
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

# --- пароли приложений (plaintext) для ALTER USER на новой ВМ ---
echo "==> meta/app-passwords.env"
PASS_ENV="${DEST}/meta/app-passwords.env"
umask 077
: >"$PASS_ENV"

yaml_get() {
  # yaml_get FILE SECTION KEY  (простой YAML без сложных вложений)
  local file="$1" section="$2" key="$3"
  [[ -f "$file" ]] || return 0
  awk -v sec="$section" -v key="$key" '
    $0 ~ "^" sec ":" { insec=1; next }
    insec && /^[a-zA-Z0-9_]+:/ && $0 !~ "^[ \t]" { insec=0 }
    insec && $1 == key ":" {
      val=$2
      for (i=3; i<=NF; i++) val=val " " $i
      gsub(/["'\'']/, "", val)
      print val
      exit
    }
  ' "$file"
}

append_cred() {
  local name="$1" user="$2" pass="$3" db="${4:-}"
  [[ -n "$user" && -n "$pass" ]] || return 0
  {
    echo "${name}_USER=${user}"
    echo "${name}_PASSWORD=${pass}"
    [[ -n "$db" ]] && echo "${name}_DATABASE=${db}"
  } >>"$PASS_ENV"
}

CFG="/opt/mailpanel/config.yaml"
if [[ -f "$CFG" ]]; then
  append_cred MAILPANEL \
    "$(yaml_get "$CFG" database user)" \
    "$(yaml_get "$CFG" database password)" \
    "$(yaml_get "$CFG" database database)"
  append_cred VMAIL \
    "$(yaml_get "$CFG" vmail_database user)" \
    "$(yaml_get "$CFG" vmail_database password)" \
    "$(yaml_get "$CFG" vmail_database database)"
  append_cred AMAVISD \
    "$(yaml_get "$CFG" amavisd_database user)" \
    "$(yaml_get "$CFG" amavisd_database password)" \
    "$(yaml_get "$CFG" amavisd_database database)"
fi

# postfix/dovecot mysql maps (часто password=)
extract_cf_pass() {
  local name="$1"
  shift
  local f user="" pass=""
  for f in "$@"; do
    [[ -f "$f" ]] || continue
    user="$(awk -F= '/^user[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f" || true)"
    pass="$(awk -F= '/^password[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$f" || true)"
    if [[ -n "$user" && -n "$pass" ]]; then
      append_cred "$name" "$user" "$pass"
      return 0
    fi
  done
  return 0
}

extract_cf_pass POSTFIX_VMAIL \
  /etc/postfix/mysql/virtual_mailbox_maps.cf \
  /etc/postfix/pgsql/virtual_mailbox_maps.cf \
  /etc/postfix/mysql_virtual_mailbox_maps.cf || true

# iredapd settings.py (grep без совпадения + pipefail иначе валит весь скрипт)
if [[ -f /opt/iredapd/settings.py ]]; then
  iu="$(grep -E "^\s*iredapd_db_user\s*=" /opt/iredapd/settings.py 2>/dev/null | tail -1 | sed -E "s/.*=\s*['\"]([^'\"]+).*/\1/" || true)"
  ipw="$(grep -E "^\s*iredapd_db_password\s*=" /opt/iredapd/settings.py 2>/dev/null | tail -1 | sed -E "s/.*=\s*['\"]([^'\"]+).*/\1/" || true)"
  append_cred IREDAPD "${iu:-iredapd}" "$ipw" "iredapd" || true
fi

# roundcube
for rc in /opt/www/roundcubemail/config/config.inc.php \
          /var/www/roundcubemail/config/config.inc.php \
          /usr/share/roundcubemail/config/config.inc.php; do
  if [[ -f "$rc" ]]; then
    # db_dsnw = 'mysql://user:pass@host/db'
    dsn="$(grep -E "db_dsnw" "$rc" 2>/dev/null | head -1 || true)"
    if [[ "$dsn" =~ mysql://([^:]+):([^@]+)@[^/]+/([a-zA-Z0-9_]+) ]]; then
      append_cred ROUNDCUBE "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" || true
    fi
    break
  fi
done

chmod 600 "$PASS_ENV"
echo "  записано: $PASS_ENV"

# --- SQL: CREATE/ALTER USER + GRANT (по паролям из env) ---
echo "==> meta/mysql-users.sql"
SQL_USERS="${DEST}/meta/mysql-users.sql"
{
  echo "-- Generated by mailpanel-backup.sh at $(date -Iseconds)"
  echo "-- Apply as MySQL root on the NEW host AFTER importing databases."
  echo "SET sql_log_bin = 0;"
} >"$SQL_USERS"

add_mysql_user_sql() {
  local user="$1" pass="$2" db="$3" priv="${4:-ALL PRIVILEGES}"
  [[ -n "$user" && -n "$pass" ]] || return 0
  # экранирование ' в пароле
  local pass_esc="${pass//\'/\'\'}"
  {
    echo "CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${pass_esc}';"
    echo "ALTER USER '${user}'@'localhost' IDENTIFIED BY '${pass_esc}';"
    if [[ -n "$db" ]]; then
      echo "GRANT ${priv} ON \`${db}\`.* TO '${user}'@'localhost';"
    fi
  } >>"$SQL_USERS"
}

# читаем обратно из PASS_ENV
get_env() { grep -E "^${1}=" "$PASS_ENV" 2>/dev/null | head -1 | cut -d= -f2- || true; }

add_mysql_user_sql "$(get_env VMAIL_USER)" "$(get_env VMAIL_PASSWORD)" "$(get_env VMAIL_DATABASE)" "ALL PRIVILEGES"
# vmailadmin часто нужен для управления
if mysql "${mysql_args[@]}" -Nse "SELECT User FROM mysql.user WHERE User='vmailadmin' AND Host='localhost'" 2>/dev/null | grep -qx vmailadmin; then
  va_pass="$(grep -i 'Username:\s*vmailadmin' -A2 /root/iRedMail.tips 2>/dev/null | grep -i password | head -1 | awk '{print $NF}' || true)"
  [[ -z "$va_pass" ]] && va_pass="$(get_env VMAIL_PASSWORD)"
  add_mysql_user_sql "vmailadmin" "$va_pass" "vmail" "ALL PRIVILEGES"
fi || true
add_mysql_user_sql "$(get_env AMAVISD_USER)" "$(get_env AMAVISD_PASSWORD)" "$(get_env AMAVISD_DATABASE)" "ALL PRIVILEGES"
add_mysql_user_sql "$(get_env IREDAPD_USER)" "$(get_env IREDAPD_PASSWORD)" "$(get_env IREDAPD_DATABASE)" "ALL PRIVILEGES"
add_mysql_user_sql "$(get_env ROUNDCUBE_USER)" "$(get_env ROUNDCUBE_PASSWORD)" "$(get_env ROUNDCUBE_DATABASE)" "ALL PRIVILEGES"

mp_user="$(get_env MAILPANEL_USER)"
mp_pass="$(get_env MAILPANEL_PASSWORD)"
mp_db="$(get_env MAILPANEL_DATABASE)"
if [[ -n "$mp_user" && -n "$mp_pass" ]]; then
  if [[ "$mp_user" == "root" ]]; then
    # root на новой ВМ лучше не перетирать здесь — только app-пользователь
    echo "  mailpanel database.user=root — пароль root не меняем SQL-файлом (останется root новой ВМ;"
    echo "  в config.yaml после restore при необходимости поправьте database.password под root новой ВМ)"
    echo "-- mailpanel uses MySQL root; sync database.password in config.yaml to NEW host root" >>"$SQL_USERS"
  else
    add_mysql_user_sql "$mp_user" "$mp_pass" "${mp_db:-mailpanel}" "ALL PRIVILEGES"
  fi
fi

echo "FLUSH PRIVILEGES;" >>"$SQL_USERS"
chmod 600 "$SQL_USERS"

# права на скрипты до упаковки
if [[ -d /opt/mailpanel/scripts ]]; then
  chmod +x /opt/mailpanel/scripts/*.sh 2>/dev/null || true
fi

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
  tar -C / -czf "${DEST}/configs/configs.tar.gz" \
    --exclude='opt/mailpanel/venv' \
    --exclude='opt/mailpanel/frontend/node_modules' \
    --exclude='opt/mailpanel/.git' \
    --exclude='opt/mailpanel/**/__pycache__' \
    --exclude='opt/mailpanel/**/*.pyc' \
    "${TAR_LIST[@]}"
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
  echo "backup_format=2"
} >"${DEST}/meta/info.txt"

cp -a /etc/iredmail-release "${DEST}/meta/" 2>/dev/null || true
uname -a >"${DEST}/meta/uname.txt" 2>/dev/null || true
[[ -f "$CFG" ]] && cp -a "$CFG" "${DEST}/meta/config.yaml.sample" 2>/dev/null || true

cat >"${DEST}/meta/RESTORE.txt" <<'EOF'
Восстановление на новой ВМ:
  1) РЕД ОС 8 + iRedMail 1.7.4 MARIADB (голый)
  2) Скопировать каталог бэкапа (НЕ через git)
  3) Достать скрипт: git clone mailpanel → scripts/mailpanel-restore.sh
     ИЛИ после распаковки configs он появится в /opt/mailpanel/scripts/
  4) sudo bash /opt/mailpanel/scripts/mailpanel-restore.sh /path/to/STAMP
  5) Ввести YES

Скрипт сам:
  - накатит SQL и /var/vmail
  - выровняет MySQL-пользователей под пароли из бэкапа
  - выставит +x на scripts, SELinux restorecon
  - создаст venv и поставит Python-зависимости
  - поднимет службы
EOF

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
