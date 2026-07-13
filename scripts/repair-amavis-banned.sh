#!/bin/bash
# Быстрое восстановление amavisd после некорректного banned_namepat / archive.
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

echo "==> Убираем отдельный \$banned_namepat_re = new_RE(...)"
perl -i -0pe 's/\$banned_namepat_re\s*=\s*new_RE\s*\(.*?\)\s*;[\r\n]*/$banned_namepat_re = $banned_filename_re;\n/sg' "$CONF"

echo "==> Убираем дубликаты alias namepat"
perl -i -0pe 's/(\$banned_namepat_re\s*=\s*\$banned_filename_re\s*;\s*)+/$banned_namepat_re = $banned_filename_re;\n/sg' "$CONF"

if ! grep -q 'banned_namepat_re = $banned_filename_re' "$CONF"; then
  echo "==> Добавляем alias namepat после filename_re"
  perl -i -0pe 's/(\$banned_filename_re\s*=\s*new_RE\s*\(.*?\)\s*;)/$1\n\n$banned_namepat_re = $banned_filename_re;\n/sg' "$CONF"
fi

echo "==> Проверка синтаксиса"
if ! amavisd testconfig; then
  echo ""
  echo "ОШИБКА testconfig. Восстановите вручную:"
  echo "  sudo cp $BACKUP $CONF"
  echo "  sudo amavisd testconfig"
  echo "  sudo systemctl restart amavisd"
  exit 1
fi

echo "==> Перезапуск amavisd"
systemctl restart amavisd
sleep 1
systemctl is-active --quiet amavisd
echo "Готово: amavisd active"
