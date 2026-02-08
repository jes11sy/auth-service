import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import { SecurityConfig } from '../../config/security.config';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    try {
      // ✅ FIX: Поддержка Redis Sentinel для High Availability
      const redisMode = this.configService.get<string>('REDIS_MODE', 'standalone');
      const redisPassword = this.configService.get<string>('REDIS_PASSWORD');
      const redisDb = this.configService.get<number>('REDIS_DB', 0);
      
      const commonOptions = {
        password: redisPassword,
        db: redisDb,
        retryStrategy: (times: number) => {
          if (times > 100) {
            this.logger.error('Redis connection failed after 100 retries, stopping reconnection');
            return null;
          }
          return Math.min(times * 50, 2000);
        },
        maxRetriesPerRequest: 3,
        lazyConnect: false,
        enableReadyCheck: true,
        commandTimeout: 5000,
        connectTimeout: 10000,
        keepAlive: 30000,
      };

      if (redisMode === 'sentinel') {
        // Sentinel mode для High Availability
        const sentinelHost = this.configService.get<string>('REDIS_SENTINEL_HOST', 'redis-sentinel');
        const sentinelPort = this.configService.get<number>('REDIS_SENTINEL_PORT', 26379);
        const sentinelName = this.configService.get<string>('REDIS_SENTINEL_NAME', 'mymaster');
        
        this.logger.log(`🔄 Connecting to Redis via Sentinel: ${sentinelHost}:${sentinelPort}, master: ${sentinelName}`);
        
        this.client = new Redis({
          sentinels: [{ host: sentinelHost, port: sentinelPort }],
          name: sentinelName,
          sentinelPassword: redisPassword,
          ...commonOptions,
        });
      } else {
        // Standalone mode (default)
        const redisHost = this.configService.get<string>('REDIS_HOST', 'localhost');
        const redisPort = this.configService.get<number>('REDIS_PORT', 6379);
        
        this.logger.log(`🔄 Connecting to Redis standalone: ${redisHost}:${redisPort}`);
        
        this.client = new Redis({
          host: redisHost,
          port: redisPort,
          ...commonOptions,
        });
      }

      this.client.on('connect', () => {
        this.logger.log('✅ Redis connected successfully');
      });

      this.client.on('error', (error) => {
        this.logger.error('❌ Redis connection error:', error);
      });

      await this.client.ping();
    } catch (error) {
      this.logger.error('❌ Failed to initialize Redis', error);
      throw error;
    }
  }

  async onModuleDestroy() {
    await this.client.quit();
    this.logger.log('Redis disconnected');
  }

  // ==================== FORCE LOGOUT ====================

  /**
   * ✅ Принудительная деавторизация пользователя
   * Устанавливает флаг, который проверяется в Guard на каждом запросе
   * @param userId ID пользователя
   * @param role Роль пользователя
   * @param ttlSeconds TTL флага (должен быть >= TTL access токена, по умолчанию 15 минут)
   */
  async forceLogoutUser(
    userId: number,
    role: string,
    ttlSeconds: number = 15 * 60, // 15 минут (как у access token)
  ): Promise<void> {
    const forceLogoutKey = `force_logout:${role}:${userId}`;
    
    await this.client.setex(forceLogoutKey, ttlSeconds, '1');
    
    this.logger.log(`🔒 Force logout flag set for user ${userId} (${role}) for ${ttlSeconds}s`);
  }

  /**
   * Проверить флаг принудительной деавторизации
   */
  async isUserForcedLogout(userId: number, role: string): Promise<boolean> {
    const forceLogoutKey = `force_logout:${role}:${userId}`;
    const result = await this.client.get(forceLogoutKey);
    return result === '1';
  }

  /**
   * Очистить флаг принудительной деавторизации (при новом логине)
   */
  async clearForceLogout(userId: number, role: string): Promise<void> {
    const forceLogoutKey = `force_logout:${role}:${userId}`;
    await this.client.del(forceLogoutKey);
    this.logger.debug(`Force logout flag cleared for user ${userId} (${role})`);
  }

  // ==================== REFRESH TOKENS (SESSION-BASED) ====================

  /**
   * ✅ НОВАЯ АРХИТЕКТУРА: Хранение токенов по Session ID
   * 
   * Структура ключей:
   * - session:{role}:{userId}:{sessionId} -> refresh_token (сам токен)
   * - user_sessions:{role}:{userId} -> SET of sessionIds
   * 
   * Это решает проблему token reuse при входе с нескольких устройств:
   * - Каждое устройство имеет свой sessionId
   * - Refresh токен привязан к sessionId, а не к самому себе
   * - При refresh проверяется sessionId, а не весь токен
   */

  /**
   * Сохранить refresh токен по session ID
   * @param userId ID пользователя
   * @param role Роль пользователя
   * @param sessionId Уникальный ID сессии (из JWT payload.sid)
   * @param token Refresh токен
   * @param ttlSeconds TTL в секундах
   */
  async saveRefreshTokenBySession(
    userId: number,
    role: string,
    sessionId: string,
    token: string,
    ttlSeconds: number = 7 * 24 * 60 * 60,
  ): Promise<void> {
    const sessionKey = `session:${role}:${userId}:${sessionId}`;
    const userSessionsSet = `user_sessions:${role}:${userId}`;
    
    // Проверяем количество существующих сессий
    const currentSessionCount = await this.client.scard(userSessionsSet);
    
    if (currentSessionCount >= SecurityConfig.MAX_SESSIONS_PER_USER) {
      // Удаляем случайные старые сессии
      const sessionsToRemove = currentSessionCount - SecurityConfig.MAX_SESSIONS_PER_USER + 1;
      const oldSessions = await this.client.srandmember(userSessionsSet, sessionsToRemove);
      
      if (oldSessions && oldSessions.length > 0) {
        const pipeline = this.client.pipeline();
        for (const oldSessionId of oldSessions) {
          const oldSessionKey = `session:${role}:${userId}:${oldSessionId}`;
          pipeline.del(oldSessionKey);
          pipeline.srem(userSessionsSet, oldSessionId);
        }
        await pipeline.exec();
        
        this.logger.warn(
          `⚠️ Session limit reached for user ${userId} (${role}). ` +
          `Removed ${oldSessions.length} old session(s). Max: ${SecurityConfig.MAX_SESSIONS_PER_USER}`,
        );
      }
    }
    
    // Сохраняем сессию атомарно
    const pipeline = this.client.pipeline();
    pipeline.setex(sessionKey, ttlSeconds, token);
    pipeline.sadd(userSessionsSet, sessionId);
    pipeline.expire(userSessionsSet, ttlSeconds);
    await pipeline.exec();
    
    this.logger.debug(`Session ${sessionId.substring(0, 8)}... saved for user ${userId} (${role})`);
  }

  /**
   * Проверить валидность refresh токена по session ID
   * Возвращает true если sessionId существует И токен совпадает
   */
  async isRefreshTokenValidBySession(
    userId: number, 
    role: string, 
    sessionId: string,
    token: string,
  ): Promise<boolean> {
    if (!sessionId) {
      // Fallback для старых токенов без sessionId
      return this.isRefreshTokenValid(userId, role, token);
    }
    
    const sessionKey = `session:${role}:${userId}:${sessionId}`;
    const storedToken = await this.client.get(sessionKey);
    
    // Проверяем что токен существует И совпадает
    return storedToken === token;
  }

  /**
   * Обновить refresh токен для существующей сессии
   * Атомарно заменяет старый токен на новый
   */
  async updateSessionToken(
    userId: number,
    role: string,
    sessionId: string,
    newToken: string,
    ttlSeconds: number = 7 * 24 * 60 * 60,
  ): Promise<void> {
    const sessionKey = `session:${role}:${userId}:${sessionId}`;
    
    // Просто перезаписываем токен для этой сессии
    await this.client.setex(sessionKey, ttlSeconds, newToken);
    
    this.logger.debug(`Session ${sessionId.substring(0, 8)}... token updated for user ${userId} (${role})`);
  }

  /**
   * Удалить сессию (при logout или принудительном выходе)
   */
  async revokeSession(userId: number, role: string, sessionId: string): Promise<void> {
    const sessionKey = `session:${role}:${userId}:${sessionId}`;
    const userSessionsSet = `user_sessions:${role}:${userId}`;
    
    const pipeline = this.client.pipeline();
    pipeline.del(sessionKey);
    pipeline.srem(userSessionsSet, sessionId);
    await pipeline.exec();
    
    this.logger.debug(`Session ${sessionId.substring(0, 8)}... revoked for user ${userId} (${role})`);
  }

  /**
   * Удалить все сессии пользователя
   */
  async revokeAllUserSessions(userId: number, role: string): Promise<void> {
    const userSessionsSet = `user_sessions:${role}:${userId}`;
    
    const sessionIds = await this.client.smembers(userSessionsSet);
    
    if (sessionIds.length === 0) {
      this.logger.debug(`No sessions found for user ${userId} (${role})`);
      return;
    }
    
    const pipeline = this.client.pipeline();
    
    sessionIds.forEach(sessionId => {
      const sessionKey = `session:${role}:${userId}:${sessionId}`;
      pipeline.del(sessionKey);
    });
    
    pipeline.del(userSessionsSet);
    await pipeline.exec();
    
    this.logger.debug(`✅ All sessions revoked for user ${userId} (${role}): ${sessionIds.length} sessions deleted`);
  }

  // ==================== LEGACY REFRESH TOKENS (для обратной совместимости) ====================

  /**
   * @deprecated Используйте saveRefreshTokenBySession для новых токенов
   * Оставлено для обратной совместимости со старыми токенами без sessionId
   */
  async saveRefreshToken(
    userId: number,
    role: string,
    token: string,
    ttlSeconds: number = 7 * 24 * 60 * 60,
  ): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    const currentSessionCount = await this.client.scard(userTokensSet);
    
    if (currentSessionCount >= SecurityConfig.MAX_SESSIONS_PER_USER) {
      const tokensToRemove = currentSessionCount - SecurityConfig.MAX_SESSIONS_PER_USER + 1;
      const oldTokens = await this.client.srandmember(userTokensSet, tokensToRemove);
      
      if (oldTokens && oldTokens.length > 0) {
        const pipeline = this.client.pipeline();
        for (const oldToken of oldTokens) {
          const oldTokenKey = `refresh_token:${role}:${userId}:${oldToken}`;
          pipeline.del(oldTokenKey);
          pipeline.srem(userTokensSet, oldToken);
        }
        await pipeline.exec();
      }
    }
    
    const pipeline = this.client.pipeline();
    pipeline.setex(tokenKey, ttlSeconds, '1');
    pipeline.sadd(userTokensSet, token);
    pipeline.expire(userTokensSet, ttlSeconds);
    await pipeline.exec();
    
    this.logger.debug(`[LEGACY] Refresh token saved for user ${userId} (${role})`);
  }

  /**
   * @deprecated Используйте isRefreshTokenValidBySession для новых токенов
   */
  async isRefreshTokenValid(userId: number, role: string, token: string): Promise<boolean> {
    const key = `refresh_token:${role}:${userId}:${token}`;
    const exists = await this.client.exists(key);
    return exists === 1;
  }

  /**
   * @deprecated Используйте revokeSession для новых токенов
   */
  async revokeRefreshToken(userId: number, role: string, token: string): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    const pipeline = this.client.pipeline();
    pipeline.del(tokenKey);
    pipeline.srem(userTokensSet, token);
    await pipeline.exec();
    
    this.logger.debug(`[LEGACY] Refresh token revoked for user ${userId} (${role})`);
  }

  /**
   * Удалить все refresh токены пользователя (и новые сессии, и legacy токены)
   */
  async revokeAllUserTokens(userId: number, role: string): Promise<void> {
    // Удаляем новые сессии
    await this.revokeAllUserSessions(userId, role);
    
    // Удаляем legacy токены
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    try {
      const tokens = await this.client.smembers(userTokensSet);
      
      if (tokens.length === 0) {
        return;
      }
      
      const pipeline = this.client.pipeline();
      
      tokens.forEach(token => {
        const tokenKey = `refresh_token:${role}:${userId}:${token}`;
        pipeline.del(tokenKey);
      });
      
      pipeline.del(userTokensSet);
      await pipeline.exec();
      
      this.logger.debug(
        `✅ All legacy tokens revoked for user ${userId} (${role}): ${tokens.length} tokens deleted`,
      );
    } catch (error) {
      // Fallback на старый метод через SCAN если что-то пошло не так
      this.logger.warn(
        `⚠️ SET-based revocation failed, falling back to SCAN method for user ${userId} (${role})`,
      );
      
      await this.revokeAllUserTokensViaScan(userId, role);
    }
  }

  /**
   * Fallback метод: удаление токенов через SCAN (используется если SET метод не сработал)
   * ✅ FIX #8: Добавлен мониторинг и предупреждения о производительности
   * @private
   */
  private async revokeAllUserTokensViaScan(userId: number, role: string): Promise<void> {
    const startTime = Date.now();
    const pattern = `refresh_token:${role}:${userId}:*`;
    const keysToDelete: string[] = [];
    let cursor = '0';
    let scanIterations = 0;

    // ✅ FIX #8: Добавляем мониторинг SCAN операции
    this.logger.warn(
      `⚠️ Using SCAN fallback for token revocation (user ${userId}, role ${role}). ` +
      `This may be slow with many tokens.`,
    );

    // Используем SCAN для итеративного поиска ключей
    do {
      const result = await this.client.scan(
        cursor,
        'MATCH',
        pattern,
        'COUNT',
        100,
      );
      
      cursor = result[0];
      const keys = result[1];
      scanIterations++;
      
      if (keys.length > 0) {
        keysToDelete.push(...keys);
      }
      
      // ✅ FIX #8: Защита от бесконечного цикла при большом количестве ключей
      if (scanIterations > SecurityConfig.SCAN_MAX_ITERATIONS) {
        this.logger.error(
          `🚨 SCAN exceeded ${SecurityConfig.SCAN_MAX_ITERATIONS} iterations for user ${userId} (${role}). ` +
          `Found ${keysToDelete.length} keys so far. Breaking to prevent hang.`,
        );
        break;
      }
    } while (cursor !== '0');

    // Удаляем найденные ключи батчами
    if (keysToDelete.length > 0) {
      const batchSize = SecurityConfig.SCAN_BATCH_SIZE;
      for (let i = 0; i < keysToDelete.length; i += batchSize) {
        const batch = keysToDelete.slice(i, i + batchSize);
        await this.client.del(...batch);
      }
    }
    
    const duration = Date.now() - startTime;
    
    // ✅ FIX #8: Логируем метрики для мониторинга
    if (duration > 1000) {
      this.logger.error(
        `🐌 SLOW: SCAN token revocation took ${duration}ms for user ${userId} (${role}). ` +
        `Iterations: ${scanIterations}, Tokens deleted: ${keysToDelete.length}`,
      );
    } else {
      this.logger.debug(
        `All tokens revoked via SCAN for user ${userId} (${role}): ` +
        `${keysToDelete.length} tokens deleted in ${duration}ms (${scanIterations} iterations)`,
      );
    }
  }

  /**
   * ✅ ОПТИМИЗИРОВАНО: Удалить refresh токен с отслеживанием для детекции повторного использования
   * @param userId ID пользователя
   * @param role Роль пользователя
   * @param token Refresh токен
   * @param trackingTTL TTL для отслеживания отозванного токена (по умолчанию 1 час)
   */
  async revokeRefreshTokenWithTracking(
    userId: number,
    role: string,
    token: string,
    trackingTTL: number = 3600,
  ): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    const trackingKey = `revoked_token:${role}:${userId}:${token}`;

    // Используем pipeline для атомарности
    const pipeline = this.client.pipeline();
    pipeline.del(tokenKey);
    pipeline.srem(userTokensSet, token); // Удаляем из SET
    pipeline.setex(trackingKey, trackingTTL, '1');
    
    await pipeline.exec();
    
    this.logger.debug(
      `Refresh token revoked with tracking for user ${userId} (${role}), tracking TTL: ${trackingTTL}s`,
    );
  }

  /**
   * Проверить был ли токен недавно отозван (для детекции token reuse attack)
   * @param userId ID пользователя
   * @param role Роль пользователя
   * @param token Refresh токен
   * @returns true если токен был недавно отозван (попытка повторного использования)
   */
  async wasTokenRecentlyRevoked(
    userId: number,
    role: string,
    token: string,
  ): Promise<boolean> {
    const trackingKey = `revoked_token:${role}:${userId}:${token}`;
    const exists = await this.client.exists(trackingKey);
    return exists === 1;
  }

  // ==================== BRUTE-FORCE PROTECTION ====================

  /**
   * Записать попытку входа
   * @param identifier Уникальный идентификатор (например, "login:role")
   * @returns Текущее количество попыток
   */
  async recordLoginAttempt(identifier: string): Promise<number> {
    const key = `login_attempts:${identifier}`;
    const ttl = 10 * 60; // 10 минут
    
    const attempts = await this.client.incr(key);
    
    // Установить TTL только при первой попытке
    if (attempts === 1) {
      await this.client.expire(key, ttl);
    }
    
    return attempts;
  }

  /**
   * Получить количество попыток входа
   */
  async getLoginAttempts(identifier: string): Promise<number> {
    const key = `login_attempts:${identifier}`;
    const attempts = await this.client.get(key);
    return attempts ? parseInt(attempts, 10) : 0;
  }

  /**
   * Проверить, заблокирован ли аккаунт
   * @param identifier Уникальный идентификатор
   * @param maxAttempts Максимальное количество попыток (по умолчанию 10)
   */
  async isAccountLocked(identifier: string, maxAttempts: number = 10): Promise<boolean> {
    const attempts = await this.getLoginAttempts(identifier);
    return attempts >= maxAttempts;
  }

  /**
   * Сбросить счетчик попыток входа (при успешном входе)
   */
  async resetLoginAttempts(identifier: string): Promise<void> {
    const key = `login_attempts:${identifier}`;
    await this.client.del(key);
  }

  /**
   * Получить TTL блокировки в секундах
   */
  async getLockTTL(identifier: string): Promise<number> {
    const key = `login_attempts:${identifier}`;
    const ttl = await this.client.ttl(key);
    return ttl > 0 ? ttl : 0;
  }

  // ==================== UTILITY METHODS ====================

  /**
   * Общий метод для установки значения с TTL
   */
  async set(key: string, value: string, ttlSeconds?: number): Promise<void> {
    if (ttlSeconds) {
      await this.client.setex(key, ttlSeconds, value);
    } else {
      await this.client.set(key, value);
    }
  }

  /**
   * ✅ FIX #9: Атомарная установка значения только если ключ не существует (SETNX)
   * Оптимизация для throttling - 1 round-trip вместо GET + SET
   * @returns true если ключ был установлен, false если уже существовал
   */
  async setNX(key: string, value: string, ttlSeconds?: number): Promise<boolean> {
    if (ttlSeconds) {
      // SET key value EX seconds NX - атомарная операция
      const result = await this.client.set(key, value, 'EX', ttlSeconds, 'NX');
      return result === 'OK';
    } else {
      const result = await this.client.setnx(key, value);
      return result === 1;
    }
  }

  /**
   * Общий метод для получения значения
   */
  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
  }

  /**
   * ✅ FIX #10: Получение клиента Redis для продвинутых операций
   * Используется для batch операций и connection pooling
   */
  getClient(): Redis {
    return this.client;
  }

  /**
   * Удалить ключ
   */
  async del(key: string): Promise<void> {
    await this.client.del(key);
  }

  /**
   * Проверить подключение к Redis
   */
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.client.ping();
      return result === 'PONG';
    } catch (error) {
      this.logger.error('Redis health check failed:', error);
      return false;
    }
  }

  // ==================== REDIS PIPELINING ====================

  /**
   * ✅ ОПТИМИЗИРОВАНО: Сохранить refresh токен И сбросить счетчик попыток (pipeline)
   * Теперь также добавляет токен в SET для быстрого удаления
   */
  async saveRefreshTokenAndResetAttempts(
    userId: number,
    role: string,
    token: string,
    ttlSeconds: number,
    lockIdentifier: string,
  ): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    const attemptsKey = `login_attempts:${lockIdentifier}`;

    const pipeline = this.client.pipeline();
    
    // 1. Сохраняем токен
    pipeline.setex(tokenKey, ttlSeconds, '1');
    
    // 2. Добавляем в SET
    pipeline.sadd(userTokensSet, token);
    
    // 3. Обновляем TTL на SET
    pipeline.expire(userTokensSet, ttlSeconds);
    
    // 4. Сбрасываем попытки входа
    pipeline.del(attemptsKey);
    
    await pipeline.exec();
    
    this.logger.debug(
      `Refresh token saved with SET, login attempts reset for user ${userId} (${role}) via optimized pipeline`,
    );
  }

  // ==================== OPTIMIZED CACHE OPERATIONS ====================

  /**
   * ✅ FIX: Атомарная операция GET + SETNX для cache stampede protection
   * Выполняется за 1 round-trip через Lua script
   * @returns { cached: string | null, lockAcquired: boolean }
   */
  async getOrLock(
    cacheKey: string, 
    lockKey: string, 
    lockTTL: number = 5
  ): Promise<{ cached: string | null; lockAcquired: boolean }> {
    // Lua script: атомарно проверяет кеш и захватывает lock если кеш пуст
    const luaScript = `
      local cached = redis.call('GET', KEYS[1])
      if cached then
        return {cached, 0}
      end
      local locked = redis.call('SET', KEYS[2], '1', 'EX', ARGV[1], 'NX')
      if locked then
        return {nil, 1}
      end
      return {nil, 0}
    `;

    try {
      const result = await this.client.eval(
        luaScript, 
        2, 
        cacheKey, 
        lockKey, 
        lockTTL
      ) as [string | null, number];
      
      return {
        cached: result[0],
        lockAcquired: result[1] === 1,
      };
    } catch (error) {
      this.logger.warn(`Lua script failed, falling back to separate calls: ${error.message}`);
      // Fallback на отдельные вызовы
      const cached = await this.get(cacheKey);
      if (cached) {
        return { cached, lockAcquired: false };
      }
      const lockAcquired = await this.setNX(lockKey, '1', lockTTL);
      return { cached: null, lockAcquired };
    }
  }

  // ==================== IDEMPOTENT TOKEN REFRESH ====================

  /**
   * ✅ FIX: Сохранить результат refresh для idempotent повторных запросов
   * Позволяет избежать ложных срабатываний token reuse detection
   * при параллельных запросах refresh с одним и тем же токеном
   * 
   * @param oldTokenHash Hash старого токена (используем hash для экономии памяти)
   * @param newAccessToken Новый access token
   * @param newRefreshToken Новый refresh token
   * @param gracePeriodSeconds TTL кеша (по умолчанию 60 секунд)
   */
  async cacheRefreshResult(
    oldTokenHash: string,
    newAccessToken: string,
    newRefreshToken: string,
    gracePeriodSeconds: number = 60,
  ): Promise<void> {
    const cacheKey = `refresh_cache:${oldTokenHash}`;
    const cacheValue = JSON.stringify({ accessToken: newAccessToken, refreshToken: newRefreshToken });
    
    await this.client.setex(cacheKey, gracePeriodSeconds, cacheValue);
    
    this.logger.debug(`Refresh result cached for ${gracePeriodSeconds}s (idempotent protection)`);
  }

  /**
   * ✅ FIX: Получить закешированный результат refresh
   * Если найден - возвращаем те же токены что были сгенерированы ранее
   * 
   * @param oldTokenHash Hash старого токена
   * @returns Закешированные токены или null
   */
  async getCachedRefreshResult(
    oldTokenHash: string,
  ): Promise<{ accessToken: string; refreshToken: string } | null> {
    const cacheKey = `refresh_cache:${oldTokenHash}`;
    const cached = await this.client.get(cacheKey);
    
    if (cached) {
      this.logger.debug(`Refresh cache HIT - returning cached tokens (idempotent)`);
      return JSON.parse(cached);
    }
    
    return null;
  }

  /**
   * ✅ FIX: Создать hash токена для использования как ключ кеша
   * Используем первые 32 символа SHA256 для экономии памяти
   */
  hashToken(token: string): string {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(token).digest('hex').substring(0, 32);
  }

  // ==================== GRACEFUL DEGRADATION ====================

  /**
   * ✅ ИСПРАВЛЕНИЕ #13: Безопасное выполнение операции с fallback
   * Если Redis недоступен - логируем и продолжаем работу
   * fallbackValue может быть значением или функцией (для ленивой инициализации)
   */
  async safeExecute<T>(
    operation: () => Promise<T>,
    fallbackValue: T | (() => T) | (() => Promise<T>),
    operationName: string,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      this.logger.error(
        `Redis operation "${operationName}" failed, using fallback. Error: ${error.message}`,
      );
      // Если fallback — функция, вызываем её
      if (typeof fallbackValue === 'function') {
        return await (fallbackValue as () => T | Promise<T>)();
      }
      return fallbackValue;
    }
  }
}

