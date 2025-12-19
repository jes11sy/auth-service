# 🍪 HttpOnly Cookies - Инструкция по использованию

## ✅ Реализовано (Фаза 1 - Backend)

Auth-service теперь поддерживает **dual mode** - работает с обоими способами авторизации:
- ✅ **Старый способ**: токены в JSON response → localStorage (обратная совместимость)
- ✅ **Новый способ**: токены в httpOnly cookies (безопасно от XSS)

---

## 🔧 Как использовать httpOnly cookies

### 1. Добавить header в запросы

Все запросы к auth-service должны содержать header:

```javascript
'X-Use-Cookies': 'true'
```

### 2. Включить отправку cookies

Axios конфигурация:

```javascript
const api = axios.create({
  baseURL: 'http://localhost:5001/api/v1',
  withCredentials: true,  // ✅ ВАЖНО!
  headers: {
    'X-Use-Cookies': 'true',  // ✅ Переключаемся на cookie mode
  },
});
```

---

## 📝 Изменения в API

### Login

**Request:**
```bash
POST /api/v1/auth/login
Headers:
  X-Use-Cookies: true
  Content-Type: application/json

Body:
{
  "login": "admin",
  "password": "password",
  "role": "admin"
}
```

**Response (с cookies):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": 1,
      "login": "admin",
      "name": "Admin",
      "role": "admin"
    }
    // ❌ accessToken и refreshToken НЕ включены (они в cookies)
  }
}
```

**Cookies (httpOnly):**
```
Set-Cookie: access_token=eyJhbGc...; HttpOnly; Secure; SameSite=Strict; Max-Age=900
Set-Cookie: refresh_token=eyJhbGc...; HttpOnly; Secure; SameSite=Strict; Max-Age=604800
```

---

### Refresh Token

**Request:**
```bash
POST /api/v1/auth/refresh
Headers:
  X-Use-Cookies: true
  
# ❌ Body пустой - refresh token берется из cookies
```

**Response:**
```json
{
  "success": true,
  "data": {}  // Токены в cookies
}
```

---

### Logout

**Request:**
```bash
POST /api/v1/auth/logout
Headers:
  X-Use-Cookies: true
```

**Response:**
```json
{
  "success": true,
  "message": "Logout successful"
}
```

**Cookies:**
```
Set-Cookie: access_token=; Max-Age=0
Set-Cookie: refresh_token=; Max-Age=0
```

---

### Profile / Validate

**Request:**
```bash
GET /api/v1/auth/profile
Headers:
  X-Use-Cookies: true
  
# ❌ Authorization header НЕ нужен - токен берется из cookies
```

---

## 🔄 Обратная совместимость

### Старый способ (без X-Use-Cookies header)

**Request:**
```bash
POST /api/v1/auth/login
# НЕТ X-Use-Cookies header

Body:
{
  "login": "admin",
  "password": "password",
  "role": "admin"
}
```

**Response (JSON с токенами):**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": { ... },
    "accessToken": "eyJhbGc...",  // ✅ Токены в response
    "refreshToken": "eyJhbGc..."
  }
}
```

---

## 🔒 Безопасность cookies

### Настройки

```typescript
{
  httpOnly: true,        // ✅ Недоступен из JavaScript
  secure: true,          // ✅ Только HTTPS (в production)
  sameSite: 'strict',    // ✅ Защита от CSRF
  path: '/',
  maxAge: 15 * 60 * 1000 // Access: 15 минут
}
```

### Защита от атак

| Атака | Защита |
|-------|--------|
| **XSS** | ✅ httpOnly - токены недоступны JavaScript |
| **CSRF** | ✅ sameSite=strict |
| **Man-in-the-Middle** | ✅ secure=true (HTTPS only) |

---

## 📦 Установка зависимостей

```bash
cd api-services/auth-service
npm install
```

Новые зависимости:
- `@fastify/cookie` - работа с cookies
- `@types/cookie` - TypeScript типы

---

## 🧪 Тестирование

### С curl

```bash
# Login с cookies
curl -X POST http://localhost:5001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Use-Cookies: true" \
  -c cookies.txt \
  -d '{"login":"admin","password":"password","role":"admin"}'

# Profile с cookies
curl -X GET http://localhost:5001/api/v1/auth/profile \
  -H "X-Use-Cookies: true" \
  -b cookies.txt

# Logout
curl -X POST http://localhost:5001/api/v1/auth/logout \
  -H "X-Use-Cookies: true" \
  -b cookies.txt
```

### С Postman

1. Включить "Send cookies"
2. Добавить header `X-Use-Cookies: true`
3. После login cookies сохранятся автоматически

---

## 🚀 Деплой

### Environment Variables

```bash
# .env
NODE_ENV=production
COOKIE_SECRET=your-super-secret-key  # Для подписи cookies
CORS_ORIGIN=https://your-frontend.com

# Существующие переменные
JWT_SECRET=...
JWT_REFRESH_SECRET=...
```

### Docker

```bash
cd api-services/auth-service
docker build -t auth-service:httponly .
docker run -p 5001:5001 \
  -e NODE_ENV=production \
  -e COOKIE_SECRET=your-secret \
  auth-service:httponly
```

---

## 📊 Мониторинг

После деплоя проверить:

1. **Health check:**
```bash
curl http://localhost:5001/api/v1/auth/health
```

2. **Cookies работают:**
```bash
# Должны быть установлены cookies после login
curl -v -X POST ... -H "X-Use-Cookies: true"
# Смотрим на Set-Cookie в response headers
```

3. **CORS настроен:**
```bash
# Проверить preflight
curl -X OPTIONS http://localhost:5001/api/v1/auth/login \
  -H "Origin: https://your-frontend.com" \
  -H "Access-Control-Request-Method: POST" \
  -H "Access-Control-Request-Headers: x-use-cookies"
```

---

## ⚠️ Важные заметки

1. **CORS credentials**
   - `withCredentials: true` в axios
   - `credentials: true` в CORS настройках backend

2. **SameSite**
   - `strict` - самый безопасный
   - Работает только если фронтенд и бэкенд на одном домене
   - Для cross-domain нужен `sameSite: 'none'` + `secure: true`

3. **Localhost тестирование**
   - В dev режиме `secure: false` (HTTP работает)
   - В prod `secure: true` (только HTTPS)

4. **Refresh token**
   - Автоматически отправляется в cookie
   - Не нужен в request body
   - Автоматически обновляется при refresh

---

## 🐛 Troubleshooting

### Cookies не сохраняются

**Проблема:** После login cookies не устанавливаются

**Решение:**
- ✅ Проверить `withCredentials: true` в axios
- ✅ Проверить `credentials: true` в CORS
- ✅ Проверить `X-Use-Cookies: true` header
- ✅ Проверить `secure` настройку (должен быть false в dev)

### 401 Unauthorized на защищенных эндпоинтах

**Проблема:** Profile/Validate возвращают 401

**Решение:**
- ✅ Проверить что cookies отправляются (`withCredentials: true`)
- ✅ Проверить что `X-Use-Cookies: true` header присутствует
- ✅ Проверить что access_token cookie установлен (DevTools → Application → Cookies)

### CORS ошибки

**Проблема:** Preflight request failed

**Решение:**
- ✅ Добавить frontend URL в `CORS_ORIGIN` env variable
- ✅ Проверить что `X-Use-Cookies` в `allowedHeaders`
- ✅ Проверить `credentials: true`

---

## 📚 Дополнительные ресурсы

- [План миграции](./HTTPONLY_MIGRATION_PLAN.md) - полный план всех фаз
- [MDN: HTTP Cookies](https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies)
- [OWASP: HttpOnly](https://owasp.org/www-community/HttpOnly)


