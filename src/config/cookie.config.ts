/**
 * Конфигурация для работы с httpOnly cookies
 * Используется для безопасного хранения JWT токенов на стороне клиента
 */

export const CookieConfig = {
  // Имена cookies (префикс для избежания конфликтов)
  ACCESS_TOKEN_NAME: 'access_token',    // Обычное имя для cross-domain работы
  REFRESH_TOKEN_NAME: 'refresh_token',  // Обычное имя для cross-domain работы
  
  // Базовые настройки cookies
  COOKIE_OPTIONS: {
    httpOnly: true,                           // ✅ Защита от XSS - недоступен из JavaScript
    secure: process.env.NODE_ENV === 'production', // ✅ HTTPS только в production
    sameSite: 'none' as const,                // ✅ 'none' для cross-origin работы
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
 */
export function getCookieOptions(origin?: string, maxAge?: number): CookieOptions {
  const options: CookieOptions = {
    ...CookieConfig.COOKIE_OPTIONS,
  };
  
  if (maxAge) {
    options.maxAge = maxAge;
  }
  
  // Определяем domain на основе origin
  if (origin) {
    try {
      const url = new URL(origin);
      const hostname = url.hostname;
      
      // Если это поддомен lead-schem.ru, используем конкретный поддомен
      if (hostname.endsWith('.lead-schem.ru')) {
        // Для core.lead-schem.ru → domain: .lead-schem.ru (чтобы api.lead-schem.ru тоже получал)
        // Но с префиксом origin для изоляции
        options.domain = '.lead-schem.ru';
      } else if (hostname === 'lead-schem.ru') {
        options.domain = '.lead-schem.ru';
      } else if (hostname === 'localhost' || hostname.startsWith('localhost:')) {
        // Для localhost не устанавливаем domain
        delete options.domain;
      } else {
        // Для других доменов не устанавливаем domain (куки только для этого домена)
        delete options.domain;
      }
    } catch (err) {
      // Если origin некорректный, не устанавливаем domain
      delete options.domain;
    }
  } else {
    // Если origin не передан, не устанавливаем domain
    delete options.domain;
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

