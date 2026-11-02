#!/bin/bash
# =============================================================================
# Восстановление iRedMail 1.7.4 + MailPanel (формат бэкапа 2/3)
#
# ПРЕДПОСЫЛКИ:
#   РЕД ОС 8 + голый iRedMail 1.7.4 MARIADB + каталог бэкапа с COMPLETE
#
# Запуск:
#   sudo bash /opt/mailpanel/scripts/mailpanel-restore.sh /path/to/STAMP
#   MAILPANEL_RESTORE_CONFIRM=YES sudo -E bash ... /path/to/STAMP
#
# Автоматически (уроки переноса):
#   - SQL + /var/vmail + конфиги
#   - MySQL users из mysql-users.sql И повторно из живых dovecot/postfix/roundcube
#   - отдельный SQL-user mailpanel_app + правка config.yaml (не зависит от root/TCP)
#   - +x scripts, SELinux, venv+pip
#   - правила SpamAssassin из бэкапа (+ sa-update если есть сеть)
#   - enable --now: php-fpm, amavisd, clamd@amavisd, postfix, dovecot, nginx, ...
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
  exit 1
fi
SRC="$(cd "$SRC" && pwd)"

if [[ ! -f "$SRC/COMPLETE" ]]; then
  echo "ОШИБКА: нет $SRC/COMPLETE"
  exit 1
fi

echo "=============================================="
echo " Восстановление из: $SRC"
[[ -f "$SRC/meta/info.txt" ]] && cat "$SRC/meta/info.txt"
echo "=============================================="

if [[ "$CONFIRM" != "YES" ]]; then
  read -r -p "Введите YES для продолжения: " ans
  [[ "$ans" == "YES" ]] || { echo "Отменено"; exit 1; }
fi

EXPECTED="$(tr -d '[:space:]' <"$SRC/meta/iredmail-release" 2>/dev/null || true)"
CURRENT="$(tr -d '[:space:]' </etc/iredmail-release 2>/dev/null || true)"
if [[ -n "$EXPECTED" && -n "$CURRENT" && "$EXPECTED" != "$CURRENT" ]]; then
  echo "ПРЕДУПРЕЖДЕНИЕ: бэкап=$EXPECTED ВМ=$CURRENT"
  if [[ "$CONFIRM" != "YES" ]]; then
    read -r -p "Продолжить? [y/N]: " go
    [[ "$go" == "y" || "$go" == "Y" ]] || exit 1
  fi
fi

# убрать чужой .my.cnf с неверным паролем (частая ловушка после restore tips)
if [[ -f /root/.my.cnf ]]; then
  echo "==> /root/.my.cnf → .my.cnf.pre-restore (чтобы не мешал root)"
  mv -f /root/.my.cnf /root/.my.cnf.pre-restore || true
fi

mysql_args=()
if [[ -n "${MYSQL_ROOT_PASSWORD:-}" ]]; then
  export MYSQL_PWD="$MYSQL_ROOT_PASSWORD"
  mysql_args+=(-uroot)
else
  mysql_args+=(-uroot)
fi

if ! mysql "${mysql_args[@]}" -e "SELECT 1" &>/dev/null; then
  echo "ОШИБКА: MySQL root недоступен на ЭТОЙ ВМ (socket/пароль)."
  echo "  export MYSQL_ROOT_PASSWORD='из /root/iRedMail.tips этой ВМ'"
  echo "  sudo -E bash $0 $SRC"
  exit 1
fi

yaml_set_section_key() {
  # yaml_set_section_key FILE SECTION KEY VALUE — безопасное экранирование через python
  local file="$1" section="$2" key="$3" value="$4"
  python3 - "$file" "$section" "$key" "$value" <<'PY'
import sys
path, section, key, value = sys.argv[1:5]
lines = open(path, encoding="utf-8").read().splitlines(True)
out, in_sec, done = [], False, False
for line in lines:
    if line.startswith(section + ":"):
        in_sec = True
        out.append(line)
        continue
    if in_sec and line and line[0].isalpha() and ":" in line and not line.startswith((" ", "\t")):
        in_sec = False
    if in_sec and line.lstrip().startswith(key + ":") and not done:
        sp = line[: len(line) - len(line.lstrip())]
        esc = value.replace("\\", "\\\\").replace('"', '\\"')
        out.append(f'{sp}{key}: "{esc}"\n')
        done = True
        continue
    out.append(line)
open(path, "w", encoding="utf-8").writelines(out)
sys.exit(0 if done else 1)
PY
}

yaml_get() {
  local file="$1" section="$2" key="$3"
  [[ -f "$file" ]] || return 0
  awk -v sec="$section" -v key="$key" '
    $0 ~ "^" sec ":" { insec=1; next }
    insec && /^[a-zA-Z0-9_]+:/ && $0 !~ "^[ \t]" { insec=0 }
    insec && $1 == key ":" {
      val=$2; for (i=3;i<=NF;i++) val=val" "$i
      gsub(/["'\'']/, "", val); print val; exit
    }
  ' "$file"
}

ensure_mysql_user() {
  local user="$1" pass="$2" db="$3" priv="${4:-ALL PRIVILEGES}"
  [[ -n "$user" && -n "$pass" && "$user" != "root" ]] || return 0
  local pass_esc="${pass//\'/\'\'}"
  mysql "${mysql_args[@]}" -e \
    "CREATE USER IF NOT EXISTS '${user}'@'localhost' IDENTIFIED BY '${pass_esc}';
     ALTER USER '${user}'@'localhost' IDENTIFIED BY '${pass_esc}';
     GRANT ${priv} ON \`${db}\`.* TO '${user}'@'localhost';
     FLUSH PRIVILEGES;" 2>/dev/null \
    && echo "  MySQL user OK: ${user}@localhost → ${db}" \
    || echo "  ПРЕДУПРЕЖДЕНИЕ: не удалось создать ${user}"
}

echo "==> Останавливаем службы"
for svc in mailpanel postfix dovecot amavisd iredapd nginx php-fpm 'clamd@amavisd'; do
  systemctl stop "$svc" 2>/dev/null || true
done

echo "==> Восстановление SQL"
restore_db() {
  local db="$1" file="$SRC/sql/${db}.sql.gz"
  [[ -f "$file" ]] || { echo "  $db — нет дампа"; return; }
  echo "  $db"
  mysql "${mysql_args[@]}" -e "CREATE DATABASE IF NOT EXISTS \`${db}\` DEFAULT CHARACTER SET utf8mb4"
  gunzip -c "$file" | mysql "${mysql_args[@]}" "$db"
}
for db in vmail amavisd iredapd roundcubemail mailpanel sogo; do
  restore_db "$db"
done

echo "==> MySQL users из meta/mysql-users.sql"
if [[ -f "$SRC/meta/mysql-users.sql" ]]; then
  mysql "${mysql_args[@]}" <"$SRC/meta/mysql-users.sql" \
    && echo "  применено" \
    || echo "  предупреждение при применении (продолжаем — донастроим из конфигов)"
fi

echo "==> /var/vmail"
if [[ -f "$SRC/vmail/vmail.tar.gz" ]]; then
  if [[ -d /var/vmail && ! -d /var/vmail.pre-restore ]]; then
    mv /var/vmail /var/vmail.pre-restore
  else
    rm -rf /var/vmail
  fi
  tar -C / -xzf "$SRC/vmail/vmail.tar.gz"
  id vmail &>/dev/null && chown -R vmail:vmail /var/vmail || true
else
  echo "ОШИБКА: нет vmail.tar.gz"; exit 1
fi

echo "==> Конфиги"
if [[ -f "$SRC/configs/configs.tar.gz" ]]; then
  SAFETY="/root/pre-restore-configs-$(date +%Y%m%d_%H%M%S).tar.gz"
  tar -C / -czf "$SAFETY" etc/postfix etc/dovecot etc/amavisd opt/iredapd opt/mailpanel etc/mailpanel 2>/dev/null || true
  echo "  safety: $SAFETY"
  tar -C / -xzf "$SRC/configs/configs.tar.gz"
else
  echo "  configs.tar.gz нет"
fi

# снова убрать .my.cnf если приехал из бэкапа tips/конфигов (мы его не бэкапим, но на всякий)
[[ -f /root/.my.cnf ]] && mv -f /root/.my.cnf /root/.my.cnf.from-restore || true

echo "==> MySQL users из ВОССТАНОВЛЕННЫХ конфигов (источник истины)"
# dovecot vmail
if [[ -f /etc/dovecot/dovecot-mysql.conf ]]; then
  _line="$(grep -E '^connect\s*=' /etc/dovecot/dovecot-mysql.conf | head -1 || true)"
  _u="$(echo "$_line" | sed -n 's/.*user=\([^ ]*\).*/\1/p')"
  _p="$(echo "$_line" | sed -n 's/.*password=\([^ ]*\).*/\1/p')"
  _d="$(echo "$_line" | sed -n 's/.*dbname=\([^ ]*\).*/\1/p')"
  ensure_mysql_user "${_u:-vmail}" "$_p" "${_d:-vmail}" "SELECT"
fi
# postfix
for f in /etc/postfix/mysql/virtual_mailbox_maps.cf /etc/postfix/mysql/virtual_mailbox_domains.cf; do
  [[ -f "$f" ]] || continue
  _u="$(awk -F= '/^user[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f" || true)"
  _p="$(awk -F= '/^password[[:space:]]*=/{sub(/^[^=]*=[[:space:]]*/,""); print; exit}' "$f" || true)"
  _d="$(awk -F= '/^dbname[[:space:]]*=/{gsub(/[[:space:]]/,"",$2); print $2; exit}' "$f" || true)"
  ensure_mysql_user "$_u" "$_p" "${_d:-vmail}" "SELECT"
  break
done
# roundcube
for rc in /opt/www/roundcubemail/config/config.inc.php /var/www/roundcubemail/config/config.inc.php; do
  [[ -f "$rc" ]] || continue
  dsn="$(grep -E 'db_dsnw' "$rc" | head -1 || true)"
  if [[ "$dsn" =~ mysql://([^:]+):([^@]+)@[^/]+/([a-zA-Z0-9_]+) ]]; then
    ensure_mysql_user "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "ALL PRIVILEGES"
  fi
  break
done
# iredapd
if [[ -f /opt/iredapd/settings.py ]]; then
  iu="$(grep -E "^\s*iredapd_db_user\s*=" /opt/iredapd/settings.py | tail -1 | sed -E "s/.*=\s*['\"]([^'\"]+).*/\1/" || true)"
  ipw="$(grep -E "^\s*iredapd_db_password\s*=" /opt/iredapd/settings.py | tail -1 | sed -E "s/.*=\s*['\"]([^'\"]+).*/\1/" || true)"
  ensure_mysql_user "${iu:-iredapd}" "$ipw" "iredapd" "ALL PRIVILEGES"
fi
# vmailadmin из mailpanel config
CFG="/opt/mailpanel/config.yaml"
if [[ -f "$CFG" ]]; then
  ensure_mysql_user \
    "$(yaml_get "$CFG" vmail_database user)" \
    "$(yaml_get "$CFG" vmail_database password)" \
    "$(yaml_get "$CFG" vmail_database database)" \
    "ALL PRIVILEGES"
  ensure_mysql_user \
    "$(yaml_get "$CFG" amavisd_database user)" \
    "$(yaml_get "$CFG" amavisd_database password)" \
    "$(yaml_get "$CFG" amavisd_database database)" \
    "ALL PRIVILEGES"
fi

echo "==> MailPanel DB user (TCP, без зависимости от root password)"
# всегда свой пользователь — pymysql ходит на 127.0.0.1 с паролем
PANEL_DB_USER="mailpanel_app"
PANEL_DB_PASS="$(openssl rand -base64 24 | tr -d '/+=' | head -c 28)"
PANEL_DB_NAME="mailpanel"
if [[ -f "$CFG" ]]; then
  _db="$(yaml_get "$CFG" database database)"
  [[ -n "$_db" ]] && PANEL_DB_NAME="$_db"
fi
ensure_mysql_user "$PANEL_DB_USER" "$PANEL_DB_PASS" "$PANEL_DB_NAME" "ALL PRIVILEGES"
if [[ -f "$CFG" ]]; then
  yaml_set_section_key "$CFG" "database" "user" "$PANEL_DB_USER" || true
  yaml_set_section_key "$CFG" "database" "password" "$PANEL_DB_PASS" || true
  yaml_set_section_key "$CFG" "database" "host" "127.0.0.1" || true
  # проверка YAML
  if python3 -c "import yaml; yaml.safe_load(open('$CFG'))" 2>/dev/null; then
    echo "  config.yaml YAML OK (database → ${PANEL_DB_USER})"
  else
    echo "  ПРЕДУПРЕЖДЕНИЕ: config.yaml YAML битый — восстановите из meta/config.yaml.sample"
  fi
  echo "$PANEL_DB_PASS" > /root/.mailpanel_app_mysql_password
  chmod 600 /root/.mailpanel_app_mysql_password
fi

echo "==> Права scripts / SELinux"
if [[ -d /opt/mailpanel/scripts ]]; then
  chmod +x /opt/mailpanel/scripts/*.sh 2>/dev/null || true
  sed -i 's/\r$//' /opt/mailpanel/scripts/*.sh 2>/dev/null || true
fi
command -v restorecon &>/dev/null && restorecon -Rv /opt/mailpanel/scripts 2>/dev/null || true
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
  chcon -t bin_t /opt/mailpanel/scripts/*.sh 2>/dev/null || true
fi

echo "==> SpamAssassin rules"
if [[ -f "$SRC/meta/sa-rules.tar.gz" ]]; then
  tar -C / -xzf "$SRC/meta/sa-rules.tar.gz" 2>/dev/null && echo "  из бэкапа" || true
fi
if command -v sa-update &>/dev/null; then
  sa-update 2>/dev/null && echo "  sa-update OK" || echo "  sa-update пропущен (нет сети/GPG) — ок, если rules из бэкапа"
fi

echo "==> Python venv"
if [[ -d /opt/mailpanel/backend ]]; then
  dnf -y install python3-pip 2>/dev/null || true
  [[ -x /opt/mailpanel/venv/bin/python ]] || python3 -m venv /opt/mailpanel/venv
  /opt/mailpanel/venv/bin/pip install --upgrade pip -q
  [[ -f /opt/mailpanel/backend/requirements.txt ]] && \
    /opt/mailpanel/venv/bin/pip install -r /opt/mailpanel/backend/requirements.txt -q
  /opt/mailpanel/venv/bin/python -c "import fastapi,uvicorn,pymysql,jose,passlib,yaml" \
    && echo "  deps OK" || echo "  ПРЕДУПРЕЖДЕНИЕ: deps"
fi

if [[ -f /opt/mailpanel/scripts/mailpanel.service ]]; then
  cp -a /opt/mailpanel/scripts/mailpanel.service /etc/systemd/system/mailpanel.service
  systemctl daemon-reload
fi

echo "==> enable --now служб"
systemctl start mariadb 2>/dev/null || true
sleep 1
# php-fpm имя
PHP_SVC="php-fpm"
systemctl list-unit-files | grep -q '^php-fpm.service' || PHP_SVC=""
CLAM_SVC=""
systemctl list-unit-files | grep -q '^clamd@amavisd.service' && CLAM_SVC="clamd@amavisd"
systemctl list-unit-files | grep -q '^clamav-daemon.service' && [[ -z "$CLAM_SVC" ]] && CLAM_SVC="clamav-daemon"

for svc in $PHP_SVC $CLAM_SVC amavisd postfix dovecot iredapd nginx fail2ban mailpanel; do
  [[ -n "$svc" ]] || continue
  systemctl enable "$svc" 2>/dev/null || true
  systemctl reset-failed "$svc" 2>/dev/null || true
  systemctl restart "$svc" 2>/dev/null || systemctl start "$svc" 2>/dev/null \
    || echo "  не стартовал: $svc"
done
sleep 3

echo "==> Health-check"
echo -n "  panel DB: "
if MYSQL_PWD="$PANEL_DB_PASS" mysql -h127.0.0.1 -u"$PANEL_DB_USER" -Nse "SELECT username,role FROM ${PANEL_DB_NAME}.panel_users LIMIT 3" 2>/dev/null; then
  :
else
  echo "FAIL"
fi
echo -n "  dovecot→vmail: "
if [[ -n "${_p:-}" ]]; then
  MYSQL_PWD="$_p" mysql -h127.0.0.1 -u"${_u:-vmail}" -Nse "SELECT COUNT(*) FROM vmail.mailbox" 2>/dev/null \
    && echo "OK" || echo "FAIL"
else
  echo "skip"
fi
echo -n "  port 10024: "
ss -lntp 2>/dev/null | grep -q ':10024' && echo OK || echo "FAIL (amavis)"
echo -n "  clam socket: "
[[ -S /var/run/clamd.amavisd/clamd.socket ]] && echo OK || echo "нет (AV warn возможен)"

echo ""
echo "==> Статус"
for svc in mariadb postfix dovecot amavisd iredapd nginx php-fpm mailpanel $CLAM_SVC; do
  [[ -n "$svc" ]] || continue
  printf "  %-16s %s\n" "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo n/a)"
done

if ! systemctl is-active --quiet mailpanel 2>/dev/null; then
  journalctl -u mailpanel -n 30 --no-pager || true
fi

echo ""
echo "Готово."
echo "  MailPanel: http://127.0.0.1:8080  (логин как на проде)"
echo "  Roundcube: https://127.0.0.1/mail/  (или ваш URL)"
echo "  MySQL panel user: $PANEL_DB_USER  (пароль в /root/.mailpanel_app_mysql_password)"
