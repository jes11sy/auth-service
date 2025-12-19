# 🔐 План миграции на HttpOnly Cookies

## 📋 Текущее состояние

### Backend (auth-service)
- ✅ JWT токены (access + refresh)
- ✅ Redis для хранения refresh токенов
- ✅ Защита от brute-force и token reuse
- ❌ Токены возвращаются в JSON response

### Frontend (все версии)
- ❌ Токены хранятся в localStorage/sessionStorage
- ❌ Уязвимость к XSS атакам
- ✅ Автоматическое обновление токенов через interceptors

---

## 🎯 Цель миграции

Переход на **httpOnly cookies** для защиты от XSS:
- ✅ Токены недоступны JavaScript
- ✅ Автоматическая отправка с запросами
- ✅ Защита от CSRF через SameSite + CSRF токены
- ✅ Обратная совместимость на время миграции

---

## 📊 Стратегия миграции (3 фазы)

### **ФАЗА 1: Добавление поддержки cookies (параллельно с localStorage)**

#### Backend (auth-service)

1. **Создать Cookie Configuration**
```typescript
// src/config/cookie.config.ts
export const CookieConfig = {
  ACCESS_TOKEN_NAME: 'access_token',
  REFRESH_TOKEN_NAME: 'refresh_token',
  COOKIE_OPTIONS: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production', // HTTPS only в prod
    sameSite: 'strict' as const, // CSRF защита
    path: '/',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
  },
};
```

2. **Обновить AuthController - добавить dual mode**
```typescript
// В login endpoint добавить проверку заголовка
@Post('login')
async login(
  @Body() loginDto: LoginDto,
  @Res({ passthrough: true }) res: Response, // Для установки cookies
  @Headers('x-use-cookies') useCookies?: string, // Новый заголовок
) {
  const result = await this.authService.login(loginDto, ip, userAgent);
  
  // DUAL MODE: поддержка обоих способов
  if (useCookies === 'true') {
    // Новый способ: cookies
    res.cookie(CookieConfig.ACCESS_TOKEN_NAME, result.data.accessToken, {
      ...CookieConfig.COOKIE_OPTIONS,
      maxAge: 15 * 60 * 1000, // 15 минут
    });
    res.cookie(CookieConfig.REFRESH_TOKEN_NAME, result.data.refreshToken, {
      ...CookieConfig.COOKIE_OPTIONS,
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 дней
    });
    
    // Не отправляем токены в response body
    return {
      success: true,
      message: 'Login successful',
      data: {
        user: result.data.user,
        // accessToken и refreshToken НЕ включаем
      },
    };
  }
  
  // Старый способ: JSON response (для обратной совместимости)
  return result;
}
```

3. **Создать Cookie Guard для извлечения токенов**
```typescript
// src/modules/auth/guards/cookie-jwt-auth.guard.ts
@Injectable()
export class CookieJwtAuthGuard extends JwtAuthGuard {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // Проверяем наличие токена в cookies
    const cookieToken = request.cookies?.[CookieConfig.ACCESS_TOKEN_NAME];
    
    if (cookieToken && !request.headers.authorization) {
      // Добавляем токен из cookie в заголовок для JWT strategy
      request.headers.authorization = `Bearer ${cookieToken}`;
    }
    
    return super.canActivate(context);
  }
}
```

4. **Обновить refresh endpoint**
```typescript
@Post('refresh')
async refresh(
  @Body() body: RefreshTokenDto, // Старый способ
  @Req() req: Request, // Для чтения cookies
  @Res({ passthrough: true }) res: Response, // Для установки новых cookies
  @Headers('x-use-cookies') useCookies?: string,
) {
  // DUAL MODE: получаем refresh token из cookies ИЛИ body
  const refreshToken = useCookies === 'true' 
    ? req.cookies?.[CookieConfig.REFRESH_TOKEN_NAME]
    : body.refreshToken;
  
  if (!refreshToken) {
    throw new UnauthorizedException('Refresh token not found');
  }
  
  const result = await this.authService.refreshToken(refreshToken, ip, userAgent);
  
  if (useCookies === 'true') {
    // Устанавливаем новые cookies
    res.cookie(CookieConfig.ACCESS_TOKEN_NAME, result.data.accessToken, {
      ...CookieConfig.COOKIE_OPTIONS,
      maxAge: 15 * 60 * 1000,
    });
    res.cookie(CookieConfig.REFRESH_TOKEN_NAME, result.data.refreshToken, {
      ...CookieConfig.COOKIE_OPTIONS,
      maxAge: 7 * 24 * 60 * 60 * 1000,
    });
    
    return {
      success: true,
      data: {}, // Пустой объект, токены в cookies
    };
  }
  
  return result;
}
```

5. **Обновить logout endpoint**
```typescript
@Post('logout')
async logout(
  @Req() req: Request,
  @Res({ passthrough: true }) res: Response,
  @Headers('x-use-cookies') useCookies?: string,
) {
  await this.authService.logout(req.user, ip, userAgent);
  
  if (useCookies === 'true') {
    // Очищаем cookies
    res.clearCookie(CookieConfig.ACCESS_TOKEN_NAME);
    res.clearCookie(CookieConfig.REFRESH_TOKEN_NAME);
  }
  
  return { success: true, message: 'Logout successful' };
}
```

6. **Установить cookie-parser**
```bash
npm install cookie-parser
npm install -D @types/cookie-parser
```

7. **Настроить в main.ts**
```typescript
import * as cookieParser from 'cookie-parser';

app.use(cookieParser());
app.enableCors({
  origin: process.env.FRONTEND_URLS?.split(',') || ['http://localhost:3000'],
  credentials: true, // ВАЖНО: разрешаем отправку cookies
});
```

---

### **ФАЗА 2: Обновление фронтендов (поочередно)**

#### Frontend Changes (для каждого фронтенда)

1. **Обновить API client для работы с cookies**
```typescript
// src/lib/api.ts
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  withCredentials: true, // ВАЖНО: отправка cookies
  headers: {
    'X-Use-Cookies': 'true', // Сигнал для backend
  },
});

// Убрать interceptor для добавления Authorization header
// (токены теперь автоматически отправляются в cookies)
```

2. **Обновить login функцию**
```typescript
async function login(credentials: LoginCredentials) {
  const response = await api.post('/auth/login', credentials);
  
  // Токены теперь в cookies - НЕ сохраняем в localStorage
  // Только сохраняем информацию о пользователе
  if (response.data.success) {
    localStorage.setItem('user', JSON.stringify(response.data.data.user));
  }
  
  return response.data;
}
```

3. **Обновить refresh логику**
```typescript
// Interceptor для обновления токена
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401 && !error.config._retry) {
      error.config._retry = true;
      
      try {
        // Refresh token автоматически отправляется в cookies
        await api.post('/auth/refresh', {});
        
        // Повторяем оригинальный запрос
        return api.request(error.config);
      } catch {
        // Refresh failed - редирект на login
        localStorage.clear();
        window.location.href = '/login';
      }
    }
    
    return Promise.reject(error);
  }
);
```

4. **Обновить logout**
```typescript
async function logout() {
  await api.post('/auth/logout');
  localStorage.clear(); // Очищаем только user data
  window.location.href = '/login';
}
```

5. **Обновить AuthGuard**
```typescript
// Убрать проверку localStorage для токенов
// Проверяем только через API запрос (токены в cookies)
const checkAuth = async () => {
  try {
    await apiClient.getProfile(); // Токен отправляется автоматически
    setIsAuthenticated(true);
  } catch {
    router.push('/login');
  }
};
```

---

### **ФАЗА 3: Очистка и удаление старого кода**

После того как все фронтенды переведены на cookies:

1. **Backend: удалить dual mode**
   - Убрать проверку `x-use-cookies` header
   - Всегда использовать cookies
   - Убрать отправку токенов в response body

2. **Frontend: очистить код**
   - Удалить все упоминания localStorage для токенов
   - Очистить старые storage utils

3. **Документация**
   - Обновить API документацию
   - Обновить README

---

## 🔒 Дополнительная безопасность

### CSRF Protection (опционально)

После миграции на cookies, добавить CSRF защиту:

```typescript
// Backend: генерация CSRF токена
@Get('csrf-token')
async getCsrfToken(@Res({ passthrough: true }) res: Response) {
  const csrfToken = generateRandomToken();
  
  res.cookie('csrf_token', csrfToken, {
    httpOnly: false, // Должен быть доступен JS
    secure: true,
    sameSite: 'strict',
  });
  
  return { csrfToken };
}

// Frontend: добавление CSRF токена в запросы
api.interceptors.request.use((config) => {
  const csrfToken = getCookie('csrf_token');
  if (csrfToken) {
    config.headers['X-CSRF-Token'] = csrfToken;
  }
  return config;
});
```

---

## 📅 Timeline миграции

### Week 1: Фаза 1 (Backend)
- День 1-2: Реализация Cookie Configuration и dual mode
- День 3-4: Тестирование на DEV окружении
- День 5: Деплой на PROD (без breaking changes)

### Week 2-4: Фаза 2 (Frontend)
- Week 2: Frontend director (тестирование)
- Week 3: Frontend callcentre
- Week 4: Frontend master + front admin

### Week 5: Фаза 3 (Cleanup)
- Удаление старого кода
- Финальное тестирование
- Обновление документации

---

## ✅ Чеклист

### Backend
- [ ] Создать CookieConfig
- [ ] Установить cookie-parser
- [ ] Обновить main.ts (CORS + credentials)
- [ ] Обновить login endpoint (dual mode)
- [ ] Обновить refresh endpoint (dual mode)
- [ ] Обновить logout endpoint
- [ ] Создать CookieJwtAuthGuard
- [ ] Тестирование dual mode
- [ ] Деплой на DEV
- [ ] Деплой на PROD

### Frontend (для каждого)
- [ ] Добавить withCredentials в axios
- [ ] Добавить X-Use-Cookies header
- [ ] Обновить login функцию
- [ ] Обновить refresh interceptor
- [ ] Обновить logout
- [ ] Обновить AuthGuard
- [ ] Удалить token storage utils
- [ ] Тестирование
- [ ] Деплой

### Cleanup
- [ ] Удалить dual mode из backend
- [ ] Удалить старый код из frontend
- [ ] Обновить документацию
- [ ] Финальное тестирование

---

## 🚨 Риски и митигация

| Риск | Вероятность | Митигация |
|------|-------------|-----------|
| CORS проблемы | Средняя | Настроить правильные origin и credentials |
| Safari блокирует cookies | Низкая | SameSite=None + Secure для cross-site |
| Проблемы с мобильными браузерами | Низкая | Тестирование на разных устройствах |
| Пользователи остаются залогинены в старой версии | Низкая | Dual mode позволяет работать обоим |

---

## 📝 Заметки

- **Преимущества httpOnly cookies:**
  - ✅ Защита от XSS (токены недоступны JS)
  - ✅ Автоматическая отправка с каждым запросом
  - ✅ Проще управление сроками действия

- **Недостатки:**
  - ❌ Требует правильной настройки CORS
  - ❌ Нужна защита от CSRF (решается через SameSite)
  - ❌ Более сложное тестирование (cookies vs localStorage)


