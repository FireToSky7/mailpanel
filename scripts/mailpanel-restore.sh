#!/bin/bash
# =============================================================================
# Восстановление iRedMail 1.7.4 + MailPanel из бэкапа mailpanel-backup.sh
#
# ПРЕДПОСЫЛКИ на новой ВМ (ДО запуска):
#   1. РЕД ОС той же мажорной версии (у вас: 8)
#   2. Установлен iRedMail **1.7.4** MARIADB (можно «голый», без MailPanel)
#   3. Каталог бэкапа скопирован (флешка/scp), есть файл COMPLETE
#   4. Этот скрипт доступен (git clone или уже в бэкапе configs)
#
# Запуск:
#   sudo bash /opt/mailpanel/scripts/mailpanel-restore.sh /path/to/20261029_094617
#   MAILPANEL_RESTORE_CONFIRM=YES sudo -E bash ...   # без интерактива
#
# Что делает (учтены прошлые сбои):
#   - SQL-дампы + выравнивание MySQL-пользователей под пароли ИЗ БЭКАПА
#   - /var/vmail + конфиги
#   - chmod +x scripts, SELinux restorecon
#   - создание venv + pip install (venv в бэкап не кладётся)
#   - если database.user=root — подставляет пароль root НОВОЙ ВМ в config.yaml
#   - запуск служб + краткий health-check
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
  echo "Пример:       $0 /var/backups/mailpanel/20261029_094617"
  exit 1
fi

# абсолютный путь
SRC="$(cd "$SRC" && pwd)"

if [[ ! -f "$SRC/COMPLETE" ]]; then
  echo "ОШИБКА: в $SRC нет файла COMPLETE — бэкап неполный или повреждён"
  exit 1
fi

echo "=============================================="
echo " ВНИМАНИЕ: восстановление ПЕРЕЗАПИШЕТ"
echo "  - базы vmail/amavisd/iredapd/roundcubemail/mailpanel"
echo "  - MySQL-пользователей приложений (пароли → как в бэкапе)"
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

EXPECTED="$(tr -d '[:space:]' <"$SRC/meta/iredmail-release" 2>/dev/null || true)"
CURRENT="$(tr -d '[:space:]' </etc/iredmail-release 2>/dev/null || true)"
if [[ -n "$EXPECTED" && -n "$CURRENT" && "$EXPECTED" != "$CURRENT" ]]; then
  echo "ПРЕДУПРЕЖДЕНИЕ: бэкап с iRedMail $EXPECTED, на ВМ сейчас $CURRENT"
  echo "Рекомендуется одинаковая версия (1.7.4)."
  if [[ "$CONFIRM" != "YES" ]]; then
    read -r -p "Продолжить всё равно? [y/N]: " go
    [[ "$go" == "y" || "$go" == "Y" ]] || exit 1
  fi
fi

mysql_args=()
NEW_ROOT_PASS="${MYSQL_ROOT_PASSWORD:-}"
if [[ -n "$NEW_ROOT_PASS" ]]; then
  export MYSQL_PWD="$NEW_ROOT_PASS"
  mysql_args+=(-uroot)
elif [[ -f /root/.my.cnf ]]; then
  mysql_args+=(--defaults-extra-file=/root/.my.cnf)
  # попробуем вытащить пароль для правки config.yaml
  NEW_ROOT_PASS="$(awk -F= '/^password/{gsub(/[[:space:]]/,"",$2); print $2; exit}' /root/.my.cnf || true)"
else
  mysql_args+=(-uroot)
fi

if ! mysql "${mysql_args[@]}" -e "SELECT 1" &>/dev/null; then
  echo "ОШИБКА: нет доступа к MySQL root на ЭТОЙ ВМ."
  echo "Задайте: export MYSQL_ROOT_PASSWORD='...'  (из /root/iRedMail.tips этой ВМ)"
  echo "И запустите: sudo -E bash $0 $SRC"
  exit 1
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
  gunzip -c "$file" | mysql "${mysql_args[@]}" "$db"
}

for db in vmail amavisd iredapd roundcubemail mailpanel sogo; do
  restore_db "$db"
done

echo "==> MySQL-пользователи приложений (пароли из бэкапа)"
if [[ -f "$SRC/meta/mysql-users.sql" ]]; then
  mysql "${mysql_args[@]}" <"$SRC/meta/mysql-users.sql" \
    && echo "  mysql-users.sql применён" \
    || echo "  ПРЕДУПРЕЖДЕНИЕ: mysql-users.sql с ошибками (смотрите вручную)"
else
  echo "  mysql-users.sql нет (старый формат бэкапа) — пропускаем"
fi

echo "==> Восстановление /var/vmail"
if [[ -f "$SRC/vmail/vmail.tar.gz" ]]; then
  if [[ -d /var/vmail ]] && [[ ! -d /var/vmail.pre-restore ]]; then
    mv /var/vmail /var/vmail.pre-restore
  else
    rm -rf /var/vmail
  fi
  tar -C / -xzf "$SRC/vmail/vmail.tar.gz"
  if id vmail &>/dev/null; then
    chown -R vmail:vmail /var/vmail
  fi
else
  echo "  ОШИБКА: нет vmail.tar.gz"
  exit 1
fi

echo "==> Восстановление конфигов"
if [[ -f "$SRC/configs/configs.tar.gz" ]]; then
  SAFETY="/root/pre-restore-configs-$(date +%Y%m%d_%H%M%S).tar.gz"
  tar -C / -czf "$SAFETY" \
    etc/postfix etc/dovecot etc/amavisd opt/iredapd opt/mailpanel etc/mailpanel \
    2>/dev/null || true
  echo "  Текущие конфиги сохранены в $SAFETY"
  tar -C / -xzf "$SRC/configs/configs.tar.gz"
else
  echo "  configs.tar.gz нет — пропуск (только БД и почта)"
fi

echo "==> Права скриптов MailPanel / SELinux"
if [[ -d /opt/mailpanel/scripts ]]; then
  chmod +x /opt/mailpanel/scripts/*.sh 2>/dev/null || true
  # убрать CRLF на случай копирования с Windows
  for f in /opt/mailpanel/scripts/*.sh; do
    [[ -f "$f" ]] || continue
    sed -i 's/\r$//' "$f" 2>/dev/null || true
  done
fi
if command -v restorecon &>/dev/null; then
  restorecon -Rv /opt/mailpanel/scripts /opt/mailpanel/venv 2>/dev/null || true
fi
if command -v getenforce &>/dev/null && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
  # разрешить запуск скриптов из /opt при необходимости
  chcon -t bin_t /opt/mailpanel/scripts/*.sh 2>/dev/null || true
fi

# если database.user=root — пароль в yaml должен быть root НОВОЙ ВМ
CFG="/opt/mailpanel/config.yaml"
yaml_get() {
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

if [[ -f "$CFG" ]]; then
  db_user="$(yaml_get "$CFG" database user)"
  if [[ "$db_user" == "root" ]]; then
    if [[ -z "$NEW_ROOT_PASS" ]]; then
      # socket-auth: оставим пароль как есть, но предупредим
      echo "  config.yaml database.user=root; пароль root новой ВМ неизвестен скрипту."
      echo "  Если логин в панель даст «Ошибка запроса» — пропишите database.password"
      echo "  из /root/iRedMail.tips этой ВМ и: systemctl restart mailpanel"
    else
      echo "  sync database.password → root пароль НОВОЙ ВМ"
      if ! python3 - "$CFG" "$NEW_ROOT_PASS" <<'PY'
import sys
path, newpass = sys.argv[1], sys.argv[2]
lines = open(path, encoding="utf-8").read().splitlines(True)
out, in_db, done = [], False, False
for line in lines:
    if line.startswith("database:"):
        in_db = True
        out.append(line)
        continue
    if in_db and len(line) and line[0].isalpha() and ":" in line and not line.startswith((" ", "\t")):
        in_db = False
    if in_db and line.lstrip().startswith("password:") and not done:
        sp = line[: len(line) - len(line.lstrip())]
        out.append(f'{sp}password: "{newpass}"\n')
        done = True
        continue
    out.append(line)
open(path, "w", encoding="utf-8").writelines(out)
sys.exit(0 if done else 2)
PY
      then
        awk -v pass="$NEW_ROOT_PASS" '
          BEGIN{in_db=0; done=0}
          /^database:/{in_db=1; print; next}
          in_db && /^[a-zA-Z0-9_]+:/ && $0 !~ /^[ \t]/{in_db=0}
          in_db && /^[ \t]*password:/ && !done {
            match($0,/^[ \t]*/); sp=substr($0,1,RLENGTH)
            print sp "password: \"" pass "\""
            done=1; next
          }
          {print}
        ' "$CFG" >"${CFG}.tmp" && mv "${CFG}.tmp" "$CFG"
      fi
    fi
  fi
else
  echo "  ПРЕДУПРЕЖДЕНИЕ: нет $CFG — MailPanel не запустится без него"
fi

echo "==> Python venv MailPanel"
if [[ -d /opt/mailpanel/backend ]]; then
  if [[ ! -x /opt/mailpanel/venv/bin/python ]]; then
    echo "  создаём venv..."
    dnf -y install python3-pip 2>/dev/null || yum -y install python3-pip 2>/dev/null || true
    python3 -m venv /opt/mailpanel/venv
  fi
  if [[ -f /opt/mailpanel/backend/requirements.txt ]]; then
    echo "  pip install -r requirements.txt"
    /opt/mailpanel/venv/bin/pip install --upgrade pip -q
    /opt/mailpanel/venv/bin/pip install -r /opt/mailpanel/backend/requirements.txt -q
  fi
  # быстрый импорт
  if ! /opt/mailpanel/venv/bin/python -c "import fastapi, uvicorn, pymysql, jose, passlib" 2>/dev/null; then
    echo "  ПРЕДУПРЕЖДЕНИЕ: не все Python-зависимости импортируются"
  else
    echo "  зависимости OK"
  fi
else
  echo "  /opt/mailpanel/backend нет — пропуск venv"
fi

if [[ ! -f /opt/mailpanel/frontend/dist/index.html ]]; then
  echo "  ПРЕДУПРЕЖДЕНИЕ: нет frontend/dist — UI панели может не открыться."
  echo "  На ВМ с сетью: cd /opt/mailpanel/frontend && npm ci && npm run build"
fi

# systemd unit
if [[ -f /opt/mailpanel/scripts/mailpanel.service ]]; then
  cp -a /opt/mailpanel/scripts/mailpanel.service /etc/systemd/system/mailpanel.service
  systemctl daemon-reload
  systemctl enable mailpanel 2>/dev/null || true
fi

echo "==> Проверка SQL-логина панели"
if [[ -f "$CFG" ]]; then
  u="$(yaml_get "$CFG" database user)"
  p="$(yaml_get "$CFG" database password)"
  d="$(yaml_get "$CFG" database database)"
  if [[ -n "$u" && -n "$p" ]]; then
    if MYSQL_PWD="$p" mysql -u"$u" -Nse "SELECT 1" "$d" &>/dev/null; then
      echo "  OK: $u → $d"
      if MYSQL_PWD="$p" mysql -u"$u" -Nse "SELECT username,role,active FROM panel_users LIMIT 5" "$d" 2>/dev/null; then
        :
      else
        echo "  (таблица panel_users недоступна или пуста — проверьте дамп mailpanel)"
      fi
    else
      echo "  ОШИБКА: $u не может войти в $d — панель даст «Ошибка запроса»"
      echo "  Смотрите meta/app-passwords.env и database.* в config.yaml"
    fi
  fi
fi

echo "==> Запуск служб"
systemctl start mariadb mysqld 2>/dev/null || systemctl start mariadb 2>/dev/null || true
sleep 2
for svc in postfix dovecot amavisd iredapd nginx mailpanel; do
  systemctl start "$svc" 2>/dev/null || echo "  не удалось стартовать $svc (проверьте вручную)"
done
sleep 2

echo ""
echo "==> Статус"
for svc in postfix dovecot amavisd iredapd nginx mariadb mailpanel; do
  printf "  %-12s %s\n" "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo n/a)"
done

if ! systemctl is-active --quiet mailpanel 2>/dev/null; then
  echo ""
  echo "mailpanel не active — последние логи:"
  journalctl -u mailpanel -n 25 --no-pager 2>/dev/null || true
fi

echo ""
echo "Готово. Проверьте:"
echo "  1) http://127.0.0.1:8080  (не 127.0.0.0) — логин панели как на проде"
echo "  2) Roundcube / локальное письмо между ящиками"
echo "  3) journalctl -u mailpanel -n 50 --no-pager"
echo "  4) При боевом переключении — IP как у старого сервера"
echo ""
echo "Секреты бэкапа: $SRC/meta/app-passwords.env (chmod 600)"
