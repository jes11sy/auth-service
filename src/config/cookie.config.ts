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
    sameSite: 'none' as const,                // ✅ 'none' для cross-subdomain работы (strict блокирует!)
    path: '/',                                // Доступен на всех путях
    domain: '.lead-schem.ru',                 // Cross-subdomain для api.lead-schem.ru и core.lead-schem.ru
  },
  
  // TTL для cookies (Short-lived access token, long-lived refresh token)
  ACCESS_TOKEN_MAX_AGE: 15 * 60 * 1000,       // 15 минут (короткий срок для минимизации риска)
  REFRESH_TOKEN_MAX_AGE: 7 * 24 * 60 * 60 * 1000, // 7 дней
  
  // Header для переключения на cookie mode
  USE_COOKIES_HEADER: 'x-use-cookies',
  
  // Security flags
  ENABLE_COOKIE_SIGNING: true,                // Подпись cookies для защиты от tampering
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

