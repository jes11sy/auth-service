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

  // ==================== REFRESH TOKENS ====================

  /**
   * Сохранить refresh токен в Redis
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
    const key = `refresh_token:${role}:${userId}:${token}`;
    await this.client.setex(key, ttlSeconds, '1');
    this.logger.debug(`Refresh token saved for user ${userId} (${role})`);
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
   * Удалить refresh токен (при logout или refresh)
   */
  async revokeRefreshToken(userId: number, role: string, token: string): Promise<void> {
    const key = `refresh_token:${role}:${userId}:${token}`;
    await this.client.del(key);
    this.logger.debug(`Refresh token revoked for user ${userId} (${role})`);
  }

  /**
   * Удалить все refresh токены пользователя
   */
  async revokeAllUserTokens(userId: number, role: string): Promise<void> {
    const pattern = `refresh_token:${role}:${userId}:*`;
    const keys = await this.client.keys(pattern);
    if (keys.length > 0) {
      await this.client.del(...keys);
      this.logger.debug(`All tokens revoked for user ${userId} (${role})`);
    }
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
}

