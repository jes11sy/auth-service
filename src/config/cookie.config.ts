/**
 * Конфигурация для работы с httpOnly cookies
 * Используется для безопасного хранения JWT токенов на стороне клиента
 */

// ✅ FIX: Вычисляем secure и sameSite корректно
// sameSite: 'none' ТРЕБУЕТ secure: true (даже в dev через localhost с HTTPS)
const isProduction = process.env.NODE_ENV === 'production';
const useSecureCookies = isProduction || process.env.COOKIE_SECURE === 'true';

export const CookieConfig = {
  // Имена cookies (префикс для избежания конфликтов)
  ACCESS_TOKEN_NAME: 'access_token',    // Обычное имя для cross-domain работы
  REFRESH_TOKEN_NAME: 'refresh_token',  // Обычное имя для cross-domain работы
  
  // Базовые настройки cookies
  // ✅ FIX #3: sameSite: 'lax' для защиты от CSRF
  // 'lax' защищает от CSRF атак и работает между поддоменами (lead-schem.ru → api.lead-schem.ru)
  COOKIE_OPTIONS: {
    httpOnly: true,                           // ✅ Защита от XSS - недоступен из JavaScript
    secure: useSecureCookies,                 // ✅ HTTPS в production или явно включено
    sameSite: 'lax' as const,                 // ✅ FIX #3: 'lax' для CSRF защиты (работает с поддоменами)
    path: '/',                                // Доступен на всех путях
    // domain устанавливается динамически в getCookieOptions()
  },
  
  // TTL для cookies (Short-lived access token, long-lived refresh token)
  ACCESS_TOKEN_MAX_AGE: 15 * 60 * 1000,       // 15 минут (короткий срок для минимизации риска)
  REFRESH_TOKEN_MAX_AGE: 90 * 24 * 60 * 60 * 1000, // 90 дней (для устойчивости на iOS PWA)
  
  // Header для переключения на cookie mode
  USE_COOKIES_HEADER: 'x-use-cookies',
  
  // Security flags
  // ⚠️ ОТКЛЮЧЕНО: JWT уже подписан, дополнительная подпись cookie избыточна
  // и вызывает проблемы синхронизации секретов между сервисами
  ENABLE_COOKIE_SIGNING: false,
} as const;

/**
 * Типы для работы с cookies
 */
export interface CookieOptions {
  httpOnly: boolean;
  secure: boolean;
  sameSite: 'strict' | 'lax' | 'none';
  path: string;
  domain?: string;
  maxAge?: number;
}

/**
 * Проверяет, должен ли запрос использовать cookies вместо JSON
 */
export function shouldUseCookies(headers: Record<string, any>): boolean {
  const useCookiesHeader = headers[CookieConfig.USE_COOKIES_HEADER] || 
                          headers[CookieConfig.USE_COOKIES_HEADER.toUpperCase()];
  return useCookiesHeader === 'true';
}

/**
 * Получает настройки cookie с динамическим domain на основе origin запроса
 * Это изолирует куки между разными фронтендами (core.lead-schem.ru, new.lead-schem.ru и т.д.)
 * ✅ FIX #5: Используем явное присваивание вместо delete для избежания мутации
 */
export function getCookieOptions(origin?: string, maxAge?: number): CookieOptions {
  // ✅ FIX: Создаём новый объект без domain по умолчанию
  const options: CookieOptions = {
    httpOnly: CookieConfig.COOKIE_OPTIONS.httpOnly,
    secure: CookieConfig.COOKIE_OPTIONS.secure,
    sameSite: CookieConfig.COOKIE_OPTIONS.sameSite,
    path: CookieConfig.COOKIE_OPTIONS.path,
    // domain не копируется - будет установлен явно если нужно
  };
  
  if (maxAge !== undefined) {
    options.maxAge = maxAge;
  }
  
  // Определяем domain на основе origin
  if (origin) {
    try {
      const url = new URL(origin);
      const hostname = url.hostname;
      
      // Если это поддомен lead-schem.ru, используем корневой домен
      if (hostname.endsWith('.lead-schem.ru') || hostname === 'lead-schem.ru') {
        options.domain = '.lead-schem.ru';
      }
      // Для localhost и других доменов domain остаётся undefined (куки только для текущего домена)
    } catch {
      // Если origin некорректный, domain остаётся undefined
    }
  }
  
  return options;
}

/**
 * Получает уникальное имя cookie на основе origin для изоляции между фронтендами
 * Примеры:
 * - lead-schem.ru → access_token_masters (основной домен для мастеров)
 * - core.lead-schem.ru → access_token_core
 * - new.lead-schem.ru → access_token_new
 * - callcentre.lead-schem.ru → access_token_callcentre
 * - api.lead-schem.ru → access_token_api
 * - localhost → access_token_localhost
 */
export function getCookieName(baseName: string, origin?: string): string {
  if (!origin) {
    return baseName;
  }
  
  try {
    const url = new URL(origin);
    const hostname = url.hostname;
    
    // Особый случай: основной домен lead-schem.ru (без поддомена) → для мастеров
    if (hostname === 'lead-schem.ru') {
      return `${baseName}_masters`;
    }
    
    // Извлекаем поддомен (core, new, callcentre, api и т.д.)
    const parts = hostname.split('.');
    if (parts.length >= 2) {
      const subdomain = parts[0]; // core, new, callcentre, api, localhost
      // Формируем имя: access_token_core, access_token_new, access_token_callcentre
      return `${baseName}_${subdomain}`;
    }
  } catch (err) {
    // Если ошибка парсинга, используем базовое имя
  }
  
  return baseName;
}

/**
 * Устанавливает access и refresh токены в cookies
 * Используется в контроллерах и интерсепторах для единообразной установки cookies
 */
export function setCookies(
  response: any,
  accessToken: string,
  refreshToken: string,
  origin?: string,
): void {
  const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin);
  const refreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
  const accessTokenOptions = getCookieOptions(origin, CookieConfig.ACCESS_TOKEN_MAX_AGE);
  const refreshTokenOptions = getCookieOptions(origin, CookieConfig.REFRESH_TOKEN_MAX_AGE);
  
  response.setCookie(accessTokenName, accessToken, {
    ...accessTokenOptions,
    signed: CookieConfig.ENABLE_COOKIE_SIGNING,
  });
  
  response.setCookie(refreshTokenName, refreshToken, {
    ...refreshTokenOptions,
    signed: CookieConfig.ENABLE_COOKIE_SIGNING,
  });
}

