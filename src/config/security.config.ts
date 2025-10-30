/**
 * Конфигурация безопасности Auth Service
 * Все константы собраны в одном месте для упрощения управления
 */
export const SecurityConfig = {
  // Защита от brute-force атак
  MAX_LOGIN_ATTEMPTS: 10,
  LOGIN_LOCK_DURATION_SECONDS: 600, // 10 минут
  
  // Bcrypt конфигурация
  BCRYPT_ROUNDS: 12,
  
  // JWT конфигурация (значения по умолчанию, переопределяются через ENV)
  ACCESS_TOKEN_DEFAULT_TTL: '15m',
  REFRESH_TOKEN_DEFAULT_TTL: '7d',
  
  // Rate limiting (для будущей реализации)
  GLOBAL_RATE_LIMIT: 500,
  LOGIN_RATE_LIMIT: 5,
  REFRESH_RATE_LIMIT: 20,
  RATE_LIMIT_WINDOW_SECONDS: 60,
  
  // Отслеживание отозванных токенов (для детекции token reuse attack)
  REVOKED_TOKEN_TRACKING_TTL: 3600, // 1 час
  
  // Кеширование профилей
  PROFILE_CACHE_TTL: 900, // 15 минут
  
  // Преобразование времени
  SECONDS_PER_MINUTE: 60,
  SECONDS_PER_HOUR: 3600,
  SECONDS_PER_DAY: 86400,
  MINUTES_PER_HOUR: 60,
  HOURS_PER_DAY: 24,
  DAYS_PER_WEEK: 7,
  
  // Health check пороги
  DATABASE_LATENCY_THRESHOLD_MS: 1000, // 1 секунда
  REDIS_LATENCY_THRESHOLD_MS: 500, // 500 мс
  
  // Graceful shutdown
  SHUTDOWN_TIMEOUT_MS: 5000, // 5 секунд
} as const;

/**
 * Типы событий для rate limiting (для будущей реализации)
 */
export enum RateLimitType {
  GLOBAL = 'global',
  LOGIN = 'login',
  REFRESH = 'refresh',
  PROFILE = 'profile',
}

/**
 * Парсер строки времени в секунды
 * Поддерживает форматы: 15s, 15m, 15h, 7d
 */
export function parseExpirationToSeconds(expiration: string): number {
  const match = expiration.match(/^(\d+)([smhd])$/);
  if (!match) {
    return SecurityConfig.DAYS_PER_WEEK * SecurityConfig.SECONDS_PER_DAY; // по умолчанию 7 дней
  }

  const value = parseInt(match[1], 10);
  const unit = match[2];

  switch (unit) {
    case 's':
      return value;
    case 'm':
      return value * SecurityConfig.SECONDS_PER_MINUTE;
    case 'h':
      return value * SecurityConfig.SECONDS_PER_HOUR;
    case 'd':
      return value * SecurityConfig.SECONDS_PER_DAY;
    default:
      return SecurityConfig.DAYS_PER_WEEK * SecurityConfig.SECONDS_PER_DAY;
  }
}

/**
 * Преобразует секунды в минуты с округлением вверх
 */
export function secondsToMinutes(seconds: number): number {
  return Math.ceil(seconds / SecurityConfig.SECONDS_PER_MINUTE);
}

