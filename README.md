# Auth Service

Микросервис единой аутентификации для всех ролей CRM: Master, Director, Callcentre Admin, Callcentre Operator.

- Технологии: NestJS 10 + Fastify, Prisma, JWT, Swagger, Winston
- Порт: `5001`
- Префикс API: `/api/v1/auth`
- Документация: `/api/docs`

## Возможности

- Логин с выдачей пары токенов: Access + Refresh
- Валидация и обновление Access токена (с ротацией Refresh токенов)
- Инвалидация Refresh токенов через Redis
- Защита от Brute-Force атак: 10 попыток входа на 10 минут
- Полноценный Logout с отзывом всех токенов пользователя
- Получение профиля по текущему JWT
- Защита: CORS, Helmet, Rate limiting, валидация DTO
- Хеширование паролей: `bcryptjs`
- Health check с проверкой БД и Redis

## Роли и источники данных

| Роль | Таблица | Особые проверки |
|------|---------|------------------|
| admin | `callcentre_admin` | — |
| operator | `callcentre_operator` | `status === 'active'` |
| director | `director` | — |
| master | `master` | пароль должен быть задан; `statusWork === 'работает'` |

## Эндпоинты

Базовый URL: `https://api.test-shem.ru/api/v1/auth`

- `GET /health` — health check (публичный)
- `POST /login` — логин по роли, выдает `accessToken` и `refreshToken`
- `POST /refresh` — обновление `accessToken` по `refreshToken` (с ротацией токенов)
- `POST /logout` — выход из системы с отзывом всех refresh токенов (защищённый)
- `GET /validate` — проверить валидность текущего JWT (защищённый)
- `GET /profile` — получить профиль текущего пользователя (защищённый)

### Примеры запросов

#### Health
```bash
curl https://api.test-shem.ru/api/v1/auth/health
```

#### Login
```bash
curl -X POST https://api.test-shem.ru/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "login": "admin",
    "password": "password123",
    "role": "admin"  
  }'
```

Успешный ответ:
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "login": "admin",
      "name": "Администратор",
      "role": "admin",
      "cities": null,
      "city": null
    },
    "accessToken": "eyJhbGciOiJI...",
    "refreshToken": "eyJhbGciOiJI..."
  }
}
```

Ошибки:
- 401 Invalid credentials (с указанием оставшихся попыток)
- 403 Too many login attempts (блокировка на 10 минут после 10 неудачных попыток)
- 401 Invalid role
- 401 Account is not active (operator)
- 401 Master account is inactive / Password not set (master)

#### Refresh
```bash
curl -X POST https://api.test-shem.ru/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{ "refreshToken": "<REFRESH_TOKEN>" }'
```
Ответ (теперь возвращается новая пара токенов):
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJI...",
    "refreshToken": "eyJhbGciOiJI..."
  }
}
```

**Важно:** Старый refresh токен автоматически отзывается после использования (одноразовое использование). Используйте новый refresh токен из ответа.

#### Validate
```bash
curl https://api.test-shem.ru/api/v1/auth/validate \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

#### Profile
```bash
curl https://api.test-shem.ru/api/v1/auth/profile \
  -H "Authorization: Bearer <ACCESS_TOKEN>"
```

### Swagger
- Локально: `http://localhost:5001/api/docs`
- Прод: `https://api.test-shem.ru/api/v1/auth` (эндпоинты), Swagger под `/api/docs` у сервиса

## JWT

- Access: секрет `JWT_SECRET`, срок `JWT_EXPIRATION` (по умолчанию `15m`)
- Refresh: секрет `JWT_REFRESH_SECRET`, срок `JWT_REFRESH_EXPIRATION` (по умолчанию `7d`)
- Полезная нагрузка: `sub`, `login`, `role`, `name`, `cities` (для операторов: `city` также пробрасывается в ответе login)
- Refresh токены хранятся в Redis для возможности инвалидации
- При использовании refresh токен автоматически отзывается (одноразовое использование)
- При logout все refresh токены пользователя удаляются из Redis

## Переменные окружения

```env
# Сеть
PORT=5001
API_PREFIX=api/v1
CORS_ORIGIN=https://callcentre.test-shem.ru,https://dir.test-shem.ru,https://master.test-shem.ru

# JWT
JWT_SECRET=...
JWT_EXPIRATION=15m
JWT_REFRESH_SECRET=...
JWT_REFRESH_EXPIRATION=7d

# БД
DATABASE_URL=postgresql://user:password@host:5432/db

# Redis (обязательно для работы сервиса)
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=
REDIS_DB=0

# Лимиты
THROTTLE_LIMIT=100
THROTTLE_TTL=60

# Прочее
NODE_ENV=production
```

## Запуск локально

**Требования:**
- PostgreSQL (для хранения пользователей)
- Redis (для токенов и brute-force защиты)

```bash
npm install

# База данных и Prisma
npm run prisma:generate
npm run prisma:push

# Убедитесь, что Redis запущен
# docker run -d -p 6379:6379 redis:7-alpine
# или используйте локальный Redis

# старт
npm run start:dev
# Swagger: http://localhost:5001/api/docs
```

## Docker

```bash
# Build
docker build -t jes11sy/auth-service:latest .

# Run
docker run -p 5001:5001 --env-file .env jes11sy/auth-service:latest
```

CI/CD (пример): при push в `main` собирается и публикуется образ `jes11sy/auth-service`.

## Kubernetes

- Namespace: `backend`
- Ingress путь: `/api/v1/auth` → сервис `auth-service:5001`

Проверка:
```bash
kubectl get ingress backend-ingress -n backend
curl https://api.test-shem.ru/api/v1/auth/health
```

Рестарт деплоймента:
```bash
kubectl rollout restart deployment auth-service -n backend
```

## Безопасность и продакшн-настройки

- CORS: разрешенные домены из `CORS_ORIGIN` (в dev разрешено всё)
- Helmet: базовые security‑заголовки (CSP выключен в dev)
- Rate‑limiting: `THROTTLE_LIMIT` запросов за `THROTTLE_TTL` секунд
- Пароли: хеш `bcryptjs`
- Логи: Nest Logger + (опционально) Winston

## Коды ошибок

- 200/204 — успех
- 400 — валидация DTO (whitelist + forbidNonWhitelisted)
- 401 — неверные учётные данные, неверная роль, невалидный/просроченный JWT
- 403 — доступ запрещен (для защищённых эндпоинтов без нужного токена)
- 429 — превышен лимит запросов (Ingress или Fastify rate limit)
- 500 — внутренняя ошибка сервера

## Troubleshooting

- `401 Invalid credentials` — проверьте логин/пароль/роль и записи в БД
- `403 Too many login attempts` — аккаунт заблокирован на 10 минут после 10 неудачных попыток
- `401 Refresh token has been revoked` — токен уже использован или отозван через logout
- `401 Account is not active` — для операторов поле `status` должно быть `active`
- `401 Master account is inactive / Password not set` — у мастера должен быть пароль и `statusWork='работает'`
- `Invalid token` — проверьте `JWT_SECRET`/`JWT_REFRESH_SECRET` одинаковость и срок
- БД: убедитесь, что `DATABASE_URL` корректен и Prisma подключается
- Redis: проверьте подключение к Redis (`REDIS_HOST`, `REDIS_PORT`), сервис не запустится без Redis

## Структура

- `src/modules/auth/*` — контроллер, сервис, стратегии/гарды, DTO
- `src/modules/prisma/*` — Prisma клиент и подключение
- `src/modules/redis/*` — Redis клиент для управления токенами и brute-force защиты
- `prisma/schema.prisma` — модели (аутентификационные таблицы)
- `src/main.ts` — Fastify адаптер, CORS/Helmet/Rate limit, Swagger, префикс API

## Совместимость с другими сервисами

- Любой сервис может валидировать Access JWT через этот сервис (эндпоинт `/validate`)
- Фронтенды сохраняют `accessToken` и `refreshToken` и обновляют Access по необходимости через `/refresh`
- **Важно:** После `/refresh` фронтенд должен сохранить новый `refreshToken` из ответа (старый больше не валиден)
- При logout фронтенд должен удалить оба токена локально и вызвать эндпоинт `/logout` для отзыва на сервере
