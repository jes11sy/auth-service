# 🔧 Настройка переменных окружения для httpOnly Cookies

## Добавить в .env файл на сервере

```bash
# ========================================
# НОВЫЕ ПЕРЕМЕННЫЕ для httpOnly Cookies
# ========================================

# 🔒 COOKIE_SECRET - для подписи cookies (ОБЯЗАТЕЛЬНО)
# Должен быть РАЗНЫМ от JWT_SECRET и JWT_REFRESH_SECRET
# Минимум 64 символа, случайная строка
COOKIE_SECRET=генерируй_случайный_ключ_64_символа_минимум

# Генерация:
# node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# или
# openssl rand -hex 64


# ========================================
# СУЩЕСТВУЮЩИЕ ПЕРЕМЕННЫЕ (проверить)
# ========================================

# Node environment
NODE_ENV=production

# JWT секреты (должны быть РАЗНЫМИ между собой и от COOKIE_SECRET)
JWT_SECRET=твой_jwt_secret
JWT_REFRESH_SECRET=твой_refresh_secret

# CORS origins (разрешенные домены фронтендов)
CORS_ORIGIN=https://director.yourdomain.com,https://callcentre.yourdomain.com,https://master.yourdomain.com,https://admin.yourdomain.com

# Database, Redis, etc (уже есть)
DATABASE_URL=...
REDIS_URL=...
```

---

## 🔑 Генерация COOKIE_SECRET

### Вариант 1: Node.js
```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Вариант 2: OpenSSL
```bash
openssl rand -hex 64
```

### Вариант 3: Online (НЕ рекомендуется для production!)
- https://randomkeygen.com/ (только для dev!)

**Пример сгенерированного ключа:**
```
a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0e1f2g3h4i5j6k7l8m9n0o1p2q3r4s5t6u7v8w9x0y1z2
```

---

## ⚠️ ВАЖНО: Безопасность секретов

### ✅ Правильно:
```bash
COOKIE_SECRET=a1b2c3d4e5f6...длинный_случайный_ключ
JWT_SECRET=x9y8z7w6v5u4...другой_случайный_ключ
JWT_REFRESH_SECRET=m1n2o3p4q5r6...еще_один_другой_ключ
```

### ❌ НЕПРАВИЛЬНО:
```bash
# НЕ используйте одинаковые секреты!
COOKIE_SECRET=mysecret
JWT_SECRET=mysecret            # ❌ ОДИНАКОВЫЙ!
JWT_REFRESH_SECRET=mysecret     # ❌ ОДИНАКОВЫЙ!

# НЕ используйте короткие секреты!
COOKIE_SECRET=12345             # ❌ СЛИШКОМ КОРОТКИЙ!

# НЕ используйте словарные слова!
COOKIE_SECRET=password123       # ❌ ЛЕГКО ПОДОБРАТЬ!
```

---

## 🎯 __Host- Prefix

### Что это?

`__Host-` - это специальный префикс для имени cookie, который требует:
- ✅ `secure: true` (только HTTPS)
- ✅ `path: '/'`
- ✅ `domain` не установлен (cookie привязан к точному хосту)

### Уже настроено в коде

```typescript
// src/config/cookie.config.ts
ACCESS_TOKEN_NAME: '__Host-access_token'    // ✅ Уже в коде
REFRESH_TOKEN_NAME: '__Host-refresh_token'  // ✅ Уже в коде
```

**Тебе НЕ НУЖНО ничего настраивать в .env для __Host- prefix!**

Это часть имени cookie, автоматически применяется когда:
- `NODE_ENV=production` (включает `secure: true`)
- Используется HTTPS

### Как это работает?

```
БЕЗ __Host-:
Cookie: access_token=eyJhbGc...
- Может быть установлен с любого subdomain
- Может иметь domain=.example.com

С __Host-:
Cookie: __Host-access_token=eyJhbGc...
- Строго привязан к api.example.com
- НЕ может быть установлен с subdomain
- Требует HTTPS
```

---

## 🚀 Пошаговая настройка

### Шаг 1: Генерируем секрет

```bash
# На твоем сервере
COOKIE_SECRET=$(node -e "console.log(require('crypto').randomBytes(64).toString('hex'))")
echo $COOKIE_SECRET
```

### Шаг 2: Добавляем в .env

```bash
# Открываем .env файл auth-service
nano /path/to/auth-service/.env

# Добавляем строку
COOKIE_SECRET=твой_сгенерированный_ключ_из_шага_1
```

### Шаг 3: Проверяем другие переменные

```bash
# Проверяем что все секреты РАЗНЫЕ
grep "SECRET" .env

# Должно быть примерно так:
# JWT_SECRET=abc123...
# JWT_REFRESH_SECRET=xyz789...
# COOKIE_SECRET=def456...
```

### Шаг 4: Перезапускаем сервис

```bash
# Docker
docker-compose restart auth-service

# или прямой запуск
pm2 restart auth-service
```

### Шаг 5: Проверка

```bash
# Проверяем что сервис подхватил переменную
curl http://localhost:5001/api/v1/auth/health

# Логи должны показать "✅ Cookie plugin registered"
```

---

## 🧪 Тестирование после настройки

### Тест 1: Проверка COOKIE_SECRET

```bash
# Login с cookies
curl -v -X POST https://your-api.com/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Use-Cookies: true" \
  -c cookies.txt \
  -d '{"login":"admin","password":"password","role":"admin"}'

# Проверяем Set-Cookie headers
# Должно быть:
# Set-Cookie: __Host-access_token=s:eyJhbGc...; HttpOnly; Secure; SameSite=Strict
#                                  ↑
#                              s: означает signed cookie
```

### Тест 2: Проверка __Host- prefix

```bash
# Смотрим в cookies.txt
cat cookies.txt

# Должно быть:
# __Host-access_token    (с префиксом __Host-)
# __Host-refresh_token   (с префиксом __Host-)
```

### Тест 3: Проверка signed cookies

```bash
# Попытка изменить cookie вручную
# 1. Скопируй signed cookie из cookies.txt
# 2. Измени часть токена
# 3. Попробуй использовать измененный cookie

curl -X GET https://your-api.com/api/v1/auth/profile \
  -H "X-Use-Cookies: true" \
  -b "cookie_with_modified_value"

# Ожидается:
# 401 Unauthorized
# "Invalid cookie signature. Possible tampering attempt."
```

---

## 🐛 Troubleshooting

### Проблема: "COOKIE_SECRET is not defined"

**Причина:** Переменная не установлена или сервис не перезапущен

**Решение:**
```bash
# Проверить что переменная есть
grep COOKIE_SECRET .env

# Перезапустить сервис
docker-compose restart auth-service

# Проверить что переменная подхватилась
docker-compose exec auth-service printenv | grep COOKIE_SECRET
```

---

### Проблема: Cookies не работают

**Причина:** Возможно NODE_ENV != production или нет HTTPS

**Решение:**
```bash
# Проверить NODE_ENV
echo $NODE_ENV  # Должно быть 'production'

# Проверить что используется HTTPS
curl -v https://your-api.com/...  # Должен быть HTTPS, не HTTP
```

---

### Проблема: __Host- cookies не устанавливаются

**Причина:** __Host- требует `secure: true` + HTTPS

**Решение:**
- ✅ Убедись что `NODE_ENV=production`
- ✅ Убедись что используется HTTPS (не HTTP)
- ✅ Убедись что `path: '/'` (уже настроено в коде)

---

## 📋 Финальный чеклист

- [ ] `COOKIE_SECRET` добавлен в .env
- [ ] `COOKIE_SECRET` отличается от `JWT_SECRET` и `JWT_REFRESH_SECRET`
- [ ] `COOKIE_SECRET` минимум 64 символа
- [ ] `COOKIE_SECRET` случайная строка (не словарное слово)
- [ ] `NODE_ENV=production` установлен
- [ ] HTTPS настроен
- [ ] Сервис перезапущен
- [ ] Тесты пройдены (signed cookies работают)
- [ ] __Host- prefix виден в cookies (DevTools → Application → Cookies)

---

## 📝 Пример полного .env

```bash
# Node
NODE_ENV=production
PORT=5001
API_PREFIX=api/v1

# Database
DATABASE_URL=postgresql://user:pass@postgres:5432/dbname

# Redis
REDIS_URL=redis://redis:6379
REDIS_PASSWORD=your_redis_password

# JWT (ВСЕ ДОЛЖНЫ БЫТЬ РАЗНЫМИ!)
JWT_SECRET=your_jwt_secret_64_chars_min_abc123xyz789
JWT_REFRESH_SECRET=your_jwt_refresh_secret_64_chars_min_def456uvw012
JWT_EXPIRATION=15m
JWT_REFRESH_EXPIRATION=7d

# 🆕 Cookies (НОВОЕ!)
COOKIE_SECRET=your_cookie_secret_64_chars_min_ghi789rst345

# CORS
CORS_ORIGIN=https://director.yourdomain.com,https://callcentre.yourdomain.com

# Rate Limiting
THROTTLE_LIMIT=100
THROTTLE_TTL=60

# Logging
LOG_LEVEL=info
```

---

## 🎉 Готово!

После добавления `COOKIE_SECRET` в .env:
1. ✅ Signed cookies будут работать
2. ✅ __Host- prefix будет автоматически применяться (в production + HTTPS)
3. ✅ Все 8 уровней защиты активны

Можно переходить к тестированию! 🚀

