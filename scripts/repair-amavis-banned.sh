#!/bin/bash
# Быстрое восстановление amavisd после некорректного banned_namepat / namepath.
# Запуск на сервере: sudo bash /opt/mailpanel/scripts/repair-amavis-banned.sh
set -euo pipefail

CONF="/etc/amavisd/amavisd.conf"
if [[ ! -f "$CONF" ]]; then
  echo "ОШИБКА: не найден $CONF"
  exit 1
fi

BACKUP="${CONF}.bak.repair.$(date +%Y%m%d%H%M%S)"
cp -a "$CONF" "$BACKUP"
echo "==> Резервная копия: $BACKUP"

echo "==> Удаляем несуществующий \$banned_namepat_re (в Amavis есть только namepath)"
perl -i -ne 'print unless /\$banned_namepat_re/' "$CONF"
perl -i -pe 's/^\s*=\s*;\s*$//' "$CONF"

echo "==> Убираем осиротевший хвост NAMEPAT после filename_re"
perl -i -0pe 's/(# MAILPANEL_BANNED_END\s*\n\);)\s*\n+\s*#\s*MAILPANEL_NAMEPAT_BEGIN.*?\n\);/$1/sg' "$CONF"

echo "==> Синхронизируем \$banned_namepath_re со списком из \$banned_filename_re"
perl -i -0pe '
  my ($exts) = m/qr'"'"'\\.\(([^)]+)\)\$'"'"'i/s;
  if ($exts && m/\$banned_namepath_re = new_RE/s) {
    my $rule = "  # MAILPANEL_NAMEPATH_BEGIN\n  [qr'"'"'N=.*\\\\.($exts)\$'"'"'xmi => '"'"'DISCARD'"'"'],\n  # MAILPANEL_NAMEPATH_END";
    s/(\$banned_namepath_re = new_RE\()(.*?)(\)\s*;)/$1\n$rule\n$3/s;
  }
' "$CONF"

echo "==> Проверка синтаксиса"
if ! amavisd -c "$CONF" test-config 2>/dev/null && ! /usr/sbin/amavisd -c "$CONF" test-config; then
  echo ""
  echo "ОШИБКА test-config. Восстановите вручную:"
  echo "  sudo cp $BACKUP $CONF"
  echo "  sudo amavisd -c $CONF test-config"
  echo "  sudo systemctl restart amavisd"
  exit 1
fi
echo "==> Перезапуск amavisd"
systemctl restart amavisd
sleep 1
systemctl is-active --quiet amavisd
echo "Готово: amavisd active"
