# MailPanel

Собственная веб-панель управления iRedMail на РЕД ОС 8.

## Стек

- **Backend:** Python 3 + FastAPI
- **Frontend:** React + TypeScript + Vite
- **БД панели:** MariaDB (`mailpanel`)
- **БД почты:** существующие `vmail`, `amavisd`

## Роли

| Роль | Возможности |
|------|-------------|
| **superadmin** | Всё + управление админами панели |
| **admin** | Ящики, алиасы, антиспам, логи, перезапуск служб. **Пароли ящиков — только админ** |
| **viewer** | Только просмотр |
| **user** | Личный портал: пересылка, личный белый список |

## Нужен ли вход в панель обычному пользователю?

**В большинстве случаев — нет.** Пользователь работает в **Roundcube** (`https://сервер/mail`):
- читает и пишет письма;
- видит папку «Спам»;
- может помечать письма.

**Портал панели (`/portal`)** нужен только для:
- настройки **пересылки** (если не через Roundcube);
- **личного белого списка** отправителей.

Пароль от почты меняет **только админ** в разделе «Ящики».

## Установка на РЕД ОС 8

```bash
# 1. Скопируйте проект на сервер
# 2. Настройте config.yaml (пароли vmail, amavisd, mailpanel, mail_domain)
cp config.example.yaml config.yaml
nano config.yaml

# 3. Установка
sudo bash scripts/install-redos.sh

# 4. Первый вход
# http://IP:8080  →  admin / admin123
# Сразу смените пароль в «Админы панели»
```

## Ручной запуск (разработка)

```bash
# Backend
cd backend
pip install -r requirements.txt
cp ../config.example.yaml ../config.yaml
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8080

# Frontend (другой терминал)
cd frontend
npm install
npm run dev
```

## Nginx (пример)

```nginx
location /mailpanel/ {
    proxy_pass http://127.0.0.1:8080/;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}
```

## Логирование

- **Log collector** (фоновый поток) парсит `/var/log/maillog`, `iredapd`, `dovecot` → таблица `mail_log_entries`
- **Поиск** по тексту, Queue-ID, отправителю
- **Трейс** — цепочка событий одного письма по Queue-ID
- **Живой лог** — последние строки файла
- **Аудит** — действия админов в панели

## Структура проекта

```
mailpanel/
  backend/app/       # FastAPI API
  frontend/          # React UI
  scripts/           # init-db.sql, install, systemd
  config.example.yaml
```

## Дальнейшее развитие

- [ ] Карантин с просмотром тела письма
- [ ] Очередь Postfix (postqueue)
- [ ] DNS-проверка SPF/DKIM/DMARC
- [ ] Интеграция РЕД АДМ / AD
- [ ] Рассылки (mlmmj)
- [ ] Статистика и графики
