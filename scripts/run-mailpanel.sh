#!/bin/bash
# Запуск MailPanel вручную для диагностики
set -e
cd /opt/mailpanel/backend
export PYTHONPATH=/opt/mailpanel/backend

if [ ! -f /opt/mailpanel/config.yaml ]; then
  echo "ОШИБКА: нет /opt/mailpanel/config.yaml"
  echo "Выполните: sudo cp /opt/mailpanel/config.example.yaml /opt/mailpanel/config.yaml"
  exit 1
fi

if [ -x /opt/mailpanel/venv/bin/python ]; then
  PY=/opt/mailpanel/venv/bin/python
else
  PY=/usr/bin/python3
fi

echo "Python: $PY"
$PY -c "import fastapi, uvicorn, pymysql, jose, passlib; print('Зависимости OK')" || {
  echo "ОШИБКА: не установлены Python-пакеты"
  echo "Выполните: sudo pip3 install -r /opt/mailpanel/backend/requirements.txt --root-user-action=ignore"
  exit 1
}

exec $PY -m uvicorn app.main:app --host 127.0.0.1 --port 8080
