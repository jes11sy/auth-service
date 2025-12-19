import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(RedisService.name);
  private client: Redis;

  constructor(private configService: ConfigService) {}

  async onModuleInit() {
    try {
      this.client = new Redis({
        host: this.configService.get<string>('REDIS_HOST', 'localhost'),
        port: this.configService.get<number>('REDIS_PORT', 6379),
        password: this.configService.get<string>('REDIS_PASSWORD'),
        db: this.configService.get<number>('REDIS_DB', 0),
        retryStrategy: (times: number) => {
          const delay = Math.min(times * 50, 2000);
          return delay;
        },
        maxRetriesPerRequest: 3,
      });

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

  // ==================== REFRESH TOKENS ====================

  /**
   * ✅ ОПТИМИЗИРОВАНО: Сохранить refresh токен в Redis с SET для быстрого удаления всех токенов
   * @param userId ID пользователя
   * @param role Роль пользователя
   * @param token Refresh токен
   * @param ttlSeconds TTL в секундах (7 дней по умолчанию)
   */
  async saveRefreshToken(
    userId: number,
    role: string,
    token: string,
    ttlSeconds: number = 7 * 24 * 60 * 60,
  ): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    // Используем pipeline для атомарности и производительности
    const pipeline = this.client.pipeline();
    
    // 1. Сохраняем сам токен с TTL
    pipeline.setex(tokenKey, ttlSeconds, '1');
    
    // 2. Добавляем токен в SET для быстрого поиска всех токенов юзера
    pipeline.sadd(userTokensSet, token);
    
    // 3. Обновляем TTL на SET (продлеваем при каждом новом токене)
    pipeline.expire(userTokensSet, ttlSeconds);
    
    await pipeline.exec();
    
    this.logger.debug(`Refresh token saved for user ${userId} (${role}) with SET indexing`);
  }

  /**
   * Проверить существование refresh токена
   */
  async isRefreshTokenValid(userId: number, role: string, token: string): Promise<boolean> {
    const key = `refresh_token:${role}:${userId}:${token}`;
    const exists = await this.client.exists(key);
    return exists === 1;
  }

  /**
   * ✅ ОПТИМИЗИРОВАНО: Удалить refresh токен (при logout или refresh)
   */
  async revokeRefreshToken(userId: number, role: string, token: string): Promise<void> {
    const tokenKey = `refresh_token:${role}:${userId}:${token}`;
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    // Используем pipeline для атомарности
    const pipeline = this.client.pipeline();
    pipeline.del(tokenKey);
    pipeline.srem(userTokensSet, token); // Удаляем из SET
    
    await pipeline.exec();
    
    this.logger.debug(`Refresh token revoked for user ${userId} (${role})`);
  }

  /**
   * ✅ ОПТИМИЗИРОВАНО: Удалить все refresh токены пользователя за O(N) вместо O(N*M)
   * Использует Redis SET для мгновенного получения списка всех токенов юзера
   */
  async revokeAllUserTokens(userId: number, role: string): Promise<void> {
    const userTokensSet = `user_tokens:${role}:${userId}`;
    
    try {
      // Получаем все токены пользователя из SET за O(1) операцию
      const tokens = await this.client.smembers(userTokensSet);
      
      if (tokens.length === 0) {
        this.logger.debug(`No tokens found for user ${userId} (${role})`);
        return;
      }
      
      // Удаляем все токены одним pipeline запросом
      const pipeline = this.client.pipeline();
      
      // Удаляем каждый токен
      tokens.forEach(token => {
        const tokenKey = `refresh_token:${role}:${userId}:${token}`;
        pipeline.del(tokenKey);
      });
      
      // Удаляем сам SET
      pipeline.del(userTokensSet);
      
      // Выполняем все операции атомарно
      await pipeline.exec();
      
      this.logger.debug(
        `✅ All tokens revoked for user ${userId} (${role}): ${tokens.length} tokens deleted via SET optimization`,
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
   * @private
   */
  private async revokeAllUserTokensViaScan(userId: number, role: string): Promise<void> {
    const pattern = `refresh_token:${role}:${userId}:*`;
    const keysToDelete: string[] = [];
    let cursor = '0';

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
      
      if (keys.length > 0) {
        keysToDelete.push(...keys);
      }
    } while (cursor !== '0');

    // Удаляем найденные ключи батчами
    if (keysToDelete.length > 0) {
      const batchSize = 100;
      for (let i = 0; i < keysToDelete.length; i += batchSize) {
        const batch = keysToDelete.slice(i, i + batchSize);
        await this.client.del(...batch);
      }
      this.logger.debug(
        `All tokens revoked via SCAN for user ${userId} (${role}): ${keysToDelete.length} tokens deleted`,
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
   * Общий метод для получения значения
   */
  async get(key: string): Promise<string | null> {
    return await this.client.get(key);
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

  // ==================== GRACEFUL DEGRADATION ====================

  /**
   * ✅ ИСПРАВЛЕНИЕ #13: Безопасное выполнение операции с fallback
   * Если Redis недоступен - логируем и продолжаем работу
   */
  async safeExecute<T>(
    operation: () => Promise<T>,
    fallbackValue: T,
    operationName: string,
  ): Promise<T> {
    try {
      return await operation();
    } catch (error) {
      this.logger.error(
        `Redis operation "${operationName}" failed, using fallback. Error: ${error.message}`,
      );
      return fallbackValue;
    }
  }
}

