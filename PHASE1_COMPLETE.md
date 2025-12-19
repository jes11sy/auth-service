# ✅ Фаза 1 ЗАВЕРШЕНА: Backend с httpOnly Cookies

## 🎉 Что реализовано

### Новые файлы
- ✅ `src/config/cookie.config.ts` - конфигурация cookies
- ✅ `src/modules/auth/guards/cookie-jwt-auth.guard.ts` - guard для извлечения токенов из cookies
- ✅ `HTTPONLY_MIGRATION_PLAN.md` - полный план миграции
- ✅ `HTTPONLY_COOKIES_USAGE.md` - инструкция по использованию

### Обновленные файлы
- ✅ `package.json` - добавлены `@fastify/cookie` и `@types/cookie`
- ✅ `src/main.ts` - подключен cookie plugin, обновлен CORS
- ✅ `src/modules/auth/auth.controller.ts` - dual mode в login, refresh, logout, profile, validate

### Ключевые изменения

**1. Dual Mode** - поддержка обоих способов:
```typescript
// С header X-Use-Cookies: true → токены в cookies
// Без header → токены в JSON (старый способ)
```

**2. HttpOnly Cookies:**
```typescript
{
  httpOnly: true,      // ✅ Защита от XSS
  secure: true,        // ✅ Только HTTPS (prod)
  sameSite: 'strict',  // ✅ Защита от CSRF
}
```

**3. CORS обновлен:**
```typescript
credentials: true,  // Разрешаем cookies
allowedHeaders: ['X-Use-Cookies', ...]  // Новый header
```

---

## 🚀 Следующие шаги

### 1. Установить зависимости

```bash
cd api-services/auth-service
npm install
```

### 2. Обновить .env (опционально)

```bash
# Добавить secret для подписи cookies (опционально, по умолчанию использует JWT_SECRET)
COOKIE_SECRET=your-super-secret-cookie-key
```

### 3. Пересобрать сервис

```bash
# Development
npm run start:dev

# Production
npm run build
npm run start:prod

# Docker
docker build -t auth-service:httponly .
docker run -p 5001:5001 auth-service:httponly
```

### 4. Протестировать

#### Тест 1: Старый способ (обратная совместимость)

```bash
# Без X-Use-Cookies header - должны вернуться токены в JSON
curl -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "login": "admin",
    "password": "password",
    "role": "admin"
  }'

# Ответ:
# {
#   "success": true,
#   "data": {
#     "user": {...},
#     "accessToken": "eyJ...",    // ✅ Токены в JSON
#     "refreshToken": "eyJ..."
#   }
# }
```

#### Тест 2: Новый способ (cookies)

```bash
# С X-Use-Cookies: true - токены в cookies
curl -v -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Use-Cookies: true" \
  -c cookies.txt \
  -d '{
    "login": "admin",
    "password": "password",
    "role": "admin"
  }'

# В headers должны быть:
# Set-Cookie: access_token=...; HttpOnly; Secure; SameSite=Strict
# Set-Cookie: refresh_token=...; HttpOnly; Secure; SameSite=Strict

# Ответ:
# {
#   "success": true,
#   "data": {
#     "user": {...}
#     // ❌ НЕТ accessToken/refreshToken в JSON
#   }
# }
```

#### Тест 3: Использование cookies для защищенных endpoints

```bash
# Profile с cookies (без Authorization header)
curl -X GET http://localhost:5001/api/v1/auth/profile \
  -H "X-Use-Cookies: true" \
  -b cookies.txt

# Должен вернуться профиль пользователя
```

#### Тест 4: Refresh token из cookies

```bash
# Refresh без body - токен из cookies
curl -X POST http://localhost:5001/api/v1/auth/refresh \
  -H "X-Use-Cookies: true" \
  -b cookies.txt \
  -c cookies.txt

# Обновляются cookies автоматически
```

#### Тест 5: Logout

```bash
# Logout - cookies очищаются
curl -X POST http://localhost:5001/api/v1/auth/logout \
  -H "X-Use-Cookies: true" \
  -b cookies.txt

# Cookies удаляются (Max-Age=0)
```

---

## 🎯 Критерии успеха

- ✅ Старые клиенты (без X-Use-Cookies) работают как раньше
- ✅ Новые клиенты (с X-Use-Cookies) получают токены в cookies
- ✅ Cookies имеют флаги httpOnly, secure, sameSite
- ✅ Profile/Validate работают с токенами из cookies
- ✅ Refresh обновляет токены в cookies автоматически
- ✅ Logout очищает cookies
- ✅ CORS настроен правильно (credentials + headers)

---

## 📊 Проверка в production

После деплоя на DEV/PROD:

### 1. Health Check
```bash
curl http://your-server:5001/api/v1/auth/health

# Ожидаем:
# {
#   "success": true,
#   "checks": {
#     "database": true,
#     "redis": true
#   }
# }
```

### 2. CORS Preflight
```bash
curl -X OPTIONS http://your-server:5001/api/v1/auth/login \
  -H "Origin: https://your-frontend.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: x-use-cookies, content-type"

# Проверяем headers в ответе:
# Access-Control-Allow-Credentials: true
# Access-Control-Allow-Headers: ..., x-use-cookies, ...
```

### 3. Cookies с фронтенда

В DevTools → Network → Login request:
- **Request Headers:** `X-Use-Cookies: true`
- **Response Headers:** `Set-Cookie: access_token=...; HttpOnly`

В DevTools → Application → Cookies:
- ✅ `access_token` - HttpOnly, Secure, SameSite=Strict
- ✅ `refresh_token` - HttpOnly, Secure, SameSite=Strict

---

## 🔄 Следующие фазы

### Фаза 2: Frontend миграция
Обновляем фронтенды для работы с cookies:
- Week 2: Frontend director
- Week 3: Frontend callcentre
- Week 4: Frontend master + admin

### Фаза 3: Cleanup
Удаляем dual mode и старый код

---

## 📝 Дополнительно

- **Документация:** [HTTPONLY_COOKIES_USAGE.md](./HTTPONLY_COOKIES_USAGE.md)
- **План миграции:** [HTTPONLY_MIGRATION_PLAN.md](./HTTPONLY_MIGRATION_PLAN.md)
- **Swagger:** http://localhost:5001/api/docs

---

## 🐛 Возможные проблемы

### ENOENT: no such file or directory, open 'cookies.txt'
Создайте файл: `touch cookies.txt`

### Cookies не сохраняются в curl
Используйте `-c cookies.txt` для сохранения и `-b cookies.txt` для отправки

### secure: true не работает на localhost
В development mode `secure` автоматически `false` для HTTP

### CORS ошибка
Проверьте что frontend URL добавлен в `CORS_ORIGIN` env variable


