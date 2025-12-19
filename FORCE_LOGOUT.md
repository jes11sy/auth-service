# 🔒 Force Logout - Принудительная деавторизация

## Обзор

Force Logout - механизм мгновенной деавторизации пользователя администратором, который работает даже если access token еще валиден.

---

## 🎯 Проблема

**JWT токены stateless** - их нельзя отозвать до истечения срока действия (15 минут).

### Без Force Logout:
```
1. Админ удаляет refresh токены пользователя
2. ❌ Access token ещё валиден 15 минут!
3. Пользователь продолжает работать
```

### С Force Logout:
```
1. Админ вызывает /auth/admin/force-logout
2. ✅ Удаляются все refresh токены
3. ✅ Устанавливается флаг force_logout в Redis
4. ✅ МГНОВЕННАЯ деавторизация - на следующем запросе
```

---

## 🚀 Как это работает

### 1. Установка флага (при вызове force-logout)

```typescript
// Redis key
force_logout:${role}:${userId} = "1"

// TTL: 15 минут (как у access token)
```

### 2. Проверка флага (на каждом запросе)

```typescript
// В CookieJwtAuthGuard
async handleRequest(err, user, info) {
  // ... JWT валидация ...
  
  // ✅ Проверяем force_logout флаг
  const isForcedLogout = await redis.isUserForcedLogout(user.sub, user.role);
  if (isForcedLogout) {
    throw new UnauthorizedException('Session terminated by administrator');
  }
  
  return user;
}
```

### 3. Очистка флага (при новом логине)

```typescript
// В AuthService.login()
await this.redis.clearForceLogout(user.id, user.role);
```

---

## 📡 API Endpoint

### `POST /api/auth/admin/force-logout`

**Требования:**
- ✅ Авторизация (Bearer token или httpOnly cookie)
- ✅ Роль: `admin`

**Request Body:**
```json
{
  "userId": 123,
  "role": "operator"
}
```

**Response (Success):**
```json
{
  "success": true,
  "message": "User #123 (operator) has been forcefully logged out"
}
```

**Response (Errors):**
```json
// 401 Unauthorized
{
  "statusCode": 401,
  "message": "Authentication required"
}

// 403 Forbidden
{
  "statusCode": 403,
  "message": "Only administrators can force logout users"
}
```

---

## 🔧 Использование

### Из Frontend (TypeScript/React)

```typescript
const forceLogout = async (userId: number, role: string) => {
  try {
    const response = await fetch('https://api.lead-schem.ru/api/auth/admin/force-logout', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${adminToken}`,  // Или cookies
        'X-Use-Cookies': 'true',  // Если используете httpOnly cookies
      },
      credentials: 'include',  // Важно для cookies
      body: JSON.stringify({ userId, role }),
    });

    if (!response.ok) {
      throw new Error('Force logout failed');
    }

    const data = await response.json();
    console.log(data.message);
  } catch (error) {
    console.error('Error:', error);
  }
};

// Использование
await forceLogout(123, 'operator');
```

### Из curl

```bash
curl -X POST https://api.lead-schem.ru/api/auth/admin/force-logout \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -d '{"userId": 123, "role": "operator"}'
```

---

## 🛡️ Безопасность

### 1. **Только для админов**

```typescript
if (req.user.role !== 'admin') {
  throw new ForbiddenException('Only administrators can force logout users');
}
```

### 2. **Audit Logging**

```typescript
// Логируется в audit logs:
{
  "timestamp": "2025-12-19T17:30:00.000Z",
  "eventType": "auth.force_logout",
  "userId": 123,
  "role": "operator",
  "ip": "192.168.1.100",
  "metadata": {
    "adminId": 6,
    "adminRole": "admin",
    "reason": "Administrative action"
  }
}
```

### 3. **Graceful Degradation**

Если Redis недоступен:
- ❌ Флаг НЕ проверяется (graceful degradation)
- ✅ Пользователь НЕ блокируется
- ⚠️ Логируется предупреждение

```typescript
try {
  const isForcedLogout = await redis.isUserForcedLogout(userId, role);
} catch (error) {
  // ✅ Не блокируем пользователя если Redis недоступен
  console.warn('Force logout check failed:', error.message);
  return false;
}
```

---

## ⚡ Производительность

### Нагрузка на Redis:
- **+1 GET запрос** на каждый authenticated API request
- **Время выполнения:** < 1ms (Redis in-memory)
- **Масштабируемость:** миллионы запросов в секунду

### Оптимизация (опционально):
Можно добавить кеширование в памяти с TTL 10-30 секунд:

```typescript
private forceLogoutCache = new Map<string, { value: boolean; expires: number }>();

async isUserForcedLogout(userId: number, role: string): Promise<boolean> {
  const cacheKey = `${role}:${userId}`;
  const cached = this.forceLogoutCache.get(cacheKey);
  
  if (cached && cached.expires > Date.now()) {
    return cached.value;
  }
  
  const result = await redis.get(`force_logout:${role}:${userId}`);
  const value = result === '1';
  
  this.forceLogoutCache.set(cacheKey, {
    value,
    expires: Date.now() + 10000, // 10 секунд
  });
  
  return value;
}
```

---

## 🧪 Тестирование

### 1. Установить флаг вручную (Redis CLI)

```bash
# Установить флаг на 15 минут
redis-cli SETEX force_logout:operator:123 900 "1"

# Проверить флаг
redis-cli GET force_logout:operator:123
# Ответ: "1"

# Удалить флаг
redis-cli DEL force_logout:operator:123
```

### 2. Тестировать API

```bash
# 1. Логин как админ
curl -X POST https://api.lead-schem.ru/api/auth/login \
  -H "Content-Type: application/json" \
  -H "X-Use-Cookies: true" \
  -c cookies.txt \
  -d '{"login":"jessy","password":"Fuck2015@","role":"admin"}'

# 2. Force logout пользователя #123
curl -X POST https://api.lead-schem.ru/api/auth/admin/force-logout \
  -H "Content-Type: application/json" \
  -H "X-Use-Cookies: true" \
  -b cookies.txt \
  -d '{"userId":123,"role":"operator"}'

# 3. Проверить что пользователь #123 больше не может делать запросы
# (требуется токен пользователя #123 для теста)
```

---

## 📊 Мониторинг

### Redis Stats

```bash
# Количество force_logout ключей
redis-cli KEYS "force_logout:*" | wc -l

# Показать все активные force_logout флаги
redis-cli KEYS "force_logout:*"

# Проверить TTL конкретного флага
redis-cli TTL force_logout:operator:123
```

### Audit Logs

```bash
# Показать все force_logout события за сегодня
cat logs/audit.log | grep "auth.force_logout" | grep "2025-12-19"
```

---

## 🔄 Жизненный цикл

```
┌─────────────────────────────────────────────────┐
│  1. Админ вызывает /admin/force-logout          │
│     → Redis: force_logout:operator:123 = "1"    │
│     → Redis: EXPIRE 900 (15 минут)              │
│     → Удаляются все refresh токены              │
│     → Audit log: force_logout event             │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  2. Пользователь делает запрос                  │
│     → JWT валидация ✅                          │
│     → Redis: GET force_logout:operator:123      │
│     → Результат: "1" → 401 Unauthorized         │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│  3. Пользователь логинится заново               │
│     → Redis: DEL force_logout:operator:123      │
│     → Новый access + refresh токены             │
│     → Флаг очищен, работа восстановлена         │
└─────────────────────────────────────────────────┘
```

---

## ✅ Готово!

Force Logout полностью реализован и готов к использованию! 🎉

**Поддерживаемые сервисы:**
- ✅ auth-service
- ✅ reports-service
- ⚠️ Другие сервисы требуют обновления CookieJwtAuthGuard

