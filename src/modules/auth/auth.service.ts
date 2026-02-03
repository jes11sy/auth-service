import { Injectable, UnauthorizedException, Logger, ForbiddenException, OnModuleInit } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { LoginDto } from './dto/login.dto';
import { 
  UserRole, 
  AuthUser, 
  JwtPayload, 
  UserProfile, 
  LoginResponse, 
  ProfileResponse,
  RefreshTokenResponse,
} from './interfaces/auth.interface';
import { SecurityConfig, parseExpirationToSeconds, secondsToMinutes } from '../../config/security.config';
import { AuditService } from '../audit/audit.service';

@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);
  // ✅ FIX: Инициализируем синхронно fallback значением для защиты от race condition
  private dummyHash: string = '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzNGJ3zHHO';
  
  // ✅ FIX #4: In-memory rate limiter как fallback при падении Redis
  private readonly memoryRateLimiter = new Map<string, { attempts: number; lastAttempt: Date }>();
  private readonly MEMORY_LOCK_TTL_MS = 15 * 60 * 1000; // 15 минут (соответствует SecurityConfig.ACCOUNT_LOCK_DURATION)

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
    private auditService: AuditService,
  ) {}

  /**
   * ✅ FIX: Lifecycle hook - гарантирует инициализацию ДО обработки запросов
   * Это устраняет race condition - NestJS ждёт завершения onModuleInit
   */
  async onModuleInit(): Promise<void> {
    await this.initializeDummyHash();
    this.logger.log('✅ AuthService initialized successfully');
  }

  /**
   * Генерация dummy hash для защиты от timing attack
   * Выполняется асинхронно, но fallback уже установлен синхронно
   */
  private async initializeDummyHash(): Promise<void> {
    try {
      // Генерируем случайный dummy hash с уникальным seed
      const randomSeed = `dummy_${Date.now()}_${Math.random()}`;
      const newHash = await bcrypt.hash(randomSeed, SecurityConfig.BCRYPT_ROUNDS);
      this.dummyHash = newHash;
      this.logger.log('✅ Dummy hash initialized for timing attack protection');
    } catch (error) {
      // Fallback уже установлен в инициализаторе поля
      this.logger.warn('⚠️ Using fallback dummy hash due to initialization error');
    }
  }

  /**
   * ✅ FIX #4: Проверка блокировки в in-memory fallback при недоступности Redis
   */
  private checkMemoryRateLimiter(identifier: string): boolean {
    const record = this.memoryRateLimiter.get(identifier);
    if (!record) return false;
    
    // Проверяем истёк ли срок блокировки
    const isExpired = Date.now() - record.lastAttempt.getTime() > this.MEMORY_LOCK_TTL_MS;
    if (isExpired) {
      this.memoryRateLimiter.delete(identifier);
      return false;
    }
    
    return record.attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS;
  }

  /**
   * ✅ FIX #4: Регистрация неудачной попытки в in-memory fallback
   */
  private incrementMemoryRateLimiter(identifier: string): void {
    const record = this.memoryRateLimiter.get(identifier);
    const now = new Date();
    
    if (record) {
      // Если прошло больше TTL с последней попытки, сбрасываем счётчик
      const isExpired = Date.now() - record.lastAttempt.getTime() > this.MEMORY_LOCK_TTL_MS;
      if (isExpired) {
        this.memoryRateLimiter.set(identifier, { attempts: 1, lastAttempt: now });
      } else {
        record.attempts += 1;
        record.lastAttempt = now;
      }
    } else {
      this.memoryRateLimiter.set(identifier, { attempts: 1, lastAttempt: now });
    }
    
    // Очистка старых записей (garbage collection)
    this.cleanupMemoryRateLimiter();
  }

  /**
   * ✅ FIX #4: Очистка устаревших записей из in-memory rate limiter
   */
  private cleanupMemoryRateLimiter(): void {
    const now = Date.now();
    for (const [identifier, record] of this.memoryRateLimiter.entries()) {
      const isExpired = now - record.lastAttempt.getTime() > this.MEMORY_LOCK_TTL_MS;
      if (isExpired) {
        this.memoryRateLimiter.delete(identifier);
      }
    }
  }

  /**
   * Валидация пользователя по логину, паролю и роли
   * ✅ Защищено от timing attack - bcrypt.compare выполняется всегда
   * ✅ Защищено от information disclosure - единое сообщение об ошибке
   */
  async validateUser(login: string, password: string, role: string): Promise<AuthUser | null> {
    let user: any = null;

    try {
      // ✅ FIX: Загружаем только необходимые поля через select для оптимизации
      switch (role as UserRole) {
        case UserRole.ADMIN:
          user = await this.prisma.callcentreAdmin.findUnique({
            where: { login },
            select: {
              id: true,
              login: true,
              password: true,
              note: true,
            },
          });
          break;

        case UserRole.OPERATOR:
          user = await this.prisma.callcentreOperator.findUnique({
            where: { login },
            select: {
              id: true,
              name: true,
              login: true,
              password: true,
              city: true,
              status: true,
              statusWork: true,
              sipAddress: true,
            },
          });
          break;

        case UserRole.DIRECTOR:
          user = await this.prisma.director.findUnique({
            where: { login },
            select: {
              id: true,
              name: true,
              login: true,
              password: true,
              cities: true,
              tgId: true,
            },
          });
          break;

        case UserRole.MASTER:
          user = await this.prisma.master.findUnique({
            where: { login },
            select: {
              id: true,
              name: true,
              login: true,
              password: true,
              cities: true,
              statusWork: true,
              tgId: true,
              chatId: true,
            },
          });
          break;

        default:
          // ✅ ИСПРАВЛЕНИЕ: Не раскрываем что роль невалидна - просто возвращаем null
          return null;
      }

      // ✅ ИСПРАВЛЕНИЕ: ВСЕГДА выполняем bcrypt.compare для защиты от timing attack
      // Если user не найден - используем динамически сгенерированный dummy hash
      const hashToCompare = user?.password || this.dummyHash;
      const isPasswordValid = await bcrypt.compare(password, hashToCompare);

      // ✅ ИСПРАВЛЕНИЕ: Единая проверка без раскрытия деталей
      if (!user || !isPasswordValid) {
        return null; // Вызовет единое сообщение "Invalid credentials" в login()
      }

      // ✅ ИСПРАВЛЕНИЕ: Проверка дополнительных условий БЕЗ раскрытия информации
      // Просто возвращаем null - сообщение будет одинаковым для всех случаев
      if (role === UserRole.OPERATOR && user.status !== 'active') {
        return null; // Не говорим что аккаунт неактивен
      }

      if (role === UserRole.MASTER) {
        // Проверяем что пароль задан и мастер работает
        if (!user.password || user.statusWork !== 'работает') {
          return null; // Не раскрываем причину
        }
      }

      // Успешная валидация - возвращаем типизированного пользователя без пароля
      const { password: _, ...userData } = user;
      const authUser: AuthUser = {
        ...userData,
        role: role as UserRole,
      };
      return authUser;
    } catch (error) {
      // ✅ ИСПРАВЛЕНИЕ: Логируем только общую информацию без деталей
      this.logger.error(`Validation error for role: ${role}`);
      return null; // Не пробрасываем исключение наверх
    }
  }

  /**
   * Вход пользователя в систему
   * ✅ Использует константы из SecurityConfig
   * ✅ Логирует все события через AuditService
   */
  async login(loginDto: LoginDto, ip: string = '0.0.0.0', userAgent: string = 'Unknown'): Promise<LoginResponse> {
    const { login, password, role } = loginDto;

    // ✅ FIX #4: Rate limiting с fallback на in-memory при недоступности Redis
    const lockIdentifier = `${login}:${role}`;
    
    const isLocked = await this.redis.safeExecute(
      () => this.redis.isAccountLocked(lockIdentifier, SecurityConfig.MAX_LOGIN_ATTEMPTS),
      () => this.checkMemoryRateLimiter(lockIdentifier), // ✅ FIX #4: fallback на memory rate limiter
      'isAccountLocked',
    );

    if (isLocked) {
      const ttl = await this.redis.getLockTTL(lockIdentifier);
      const minutesLeft = secondsToMinutes(ttl);
      this.logger.warn(`Account locked: ${role} user (attempts exceeded)`);
      
      // ✅ AUDIT: Логируем блокировку аккаунта (await для важных событий безопасности)
      await this.auditService.logLoginBlocked(login, role as UserRole, ip, userAgent, minutesLeft);
      
      throw new ForbiddenException(
        `Too many login attempts. Try again in ${minutesLeft} minute(s).`,
      );
    }

    const user = await this.validateUser(login, password, role);

    if (!user) {
      // ✅ FIX #4: Записываем неудачную попытку с fallback на memory
      const attempts = await this.redis.safeExecute(
        () => this.redis.recordLoginAttempt(lockIdentifier),
        () => {
          // Fallback: используем in-memory rate limiter
          this.incrementMemoryRateLimiter(lockIdentifier);
          const record = this.memoryRateLimiter.get(lockIdentifier);
          return record ? record.attempts : 1;
        },
        'recordLoginAttempt',
      );
      const remainingAttempts = SecurityConfig.MAX_LOGIN_ATTEMPTS - attempts;
      
      this.logger.warn(`Failed login attempt for ${role} user (${attempts}/${SecurityConfig.MAX_LOGIN_ATTEMPTS} attempts)`);
      
      // ✅ FIX #12: Добавлен .catch() для обработки ошибок
      this.auditService.logLoginFailed(
        login, 
        role as UserRole, 
        ip, 
        userAgent, 
        'Invalid credentials',
        attempts,
      ).catch(err => this.logger.error(`Audit log failed: ${err.message}`));
      
      if (remainingAttempts > 0 && attempts > 0) {
        throw new UnauthorizedException(
          `Invalid credentials. ${remainingAttempts} attempt(s) remaining.`,
        );
      } else if (attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS) {
        throw new ForbiddenException(
          `Too many failed login attempts. Account locked for ${SecurityConfig.LOGIN_LOCK_DURATION_SECONDS / SecurityConfig.SECONDS_PER_MINUTE} minutes.`,
        );
      } else {
        throw new UnauthorizedException('Invalid credentials.');
      }
    }

    // Формируем JWT payload
    const payload: JwtPayload = {
      sub: user.id,
      login: user.login,
      role: user.role,
      name: user.name,
      cities: user.cities || undefined,
    };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL, // ✅ FIX: Используем константу (90d)
    });

    // ✅ ИСПРАВЛЕНИЕ #12: Redis Pipelining - сохраняем токен И сбрасываем attempts за 1 round trip
    const refreshTTL = SecurityConfig.REFRESH_TOKEN_TTL_SECONDS; // ✅ FIX: Используем константу
    
    await this.redis.safeExecute(
      () => this.redis.saveRefreshTokenAndResetAttempts(
        user.id,
        user.role,
        refreshToken,
        refreshTTL,
        lockIdentifier,
      ),
      undefined,
      'saveRefreshTokenAndResetAttempts',
    );

    // ✅ Очищаем флаг принудительной деавторизации при новом логине
    await this.redis.safeExecute(
      () => this.redis.clearForceLogout(user.id, user.role),
      undefined,
      'clearForceLogout',
    );

    this.logger.log(`Login successful for ${role} user`);
    
    // ✅ FIX #12: Добавлен .catch() для обработки ошибок в fire-and-forget
    this.auditService.logLoginSuccess(user.id, user.role, user.login, ip, userAgent)
      .catch(err => this.logger.error(`Audit log failed: ${err.message}`));

    return {
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          login: user.login,
          name: user.name,
          role: user.role,
          cities: user.cities,
          city: user.city, // для оператора
        },
        accessToken,
        refreshToken,
      },
    };
  }

  /**
   * Обновление access токена по refresh токену
   * ✅ Детектирует token reuse attack
   * ✅ Использует константы из SecurityConfig
   * ✅ Логирует все события через AuditService
   * ✅ FIX: Idempotent refresh - защита от ложных срабатываний при параллельных запросах
   */
  async refreshToken(
    refreshToken: string, 
    ip: string = '0.0.0.0', 
    userAgent: string = 'Unknown'
  ): Promise<RefreshTokenResponse> {
    try {
      // ✅ FIX: Явная проверка expiration с понятным сообщением
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        ignoreExpiration: false, // Явно указываем что проверяем expiration
      }) as JwtPayload;

      // ✅ FIX: Дополнительная проверка exp claim
      if (payload.exp && payload.exp * 1000 < Date.now()) {
        throw new UnauthorizedException('Refresh token has expired. Please login again.');
      }

      // ✅ FIX: Idempotent Refresh - проверяем кеш ПЕРЕД всеми проверками
      // Если этот токен уже был успешно обновлён в течение grace period,
      // возвращаем закешированные новые токены (защита от race condition)
      const tokenHash = this.redis.hashToken(refreshToken);
      const cachedResult = await this.redis.safeExecute(
        () => this.redis.getCachedRefreshResult(tokenHash),
        null,
        'getCachedRefreshResult',
      );

      if (cachedResult) {
        this.logger.log(`Idempotent refresh: returning cached tokens for ${payload.role} user`);
        return {
          success: true,
          data: cachedResult,
        };
      }

      // Проверяем, существует ли токен в Redis
      const isValid = await this.redis.isRefreshTokenValid(
        payload.sub,
        payload.role,
        refreshToken,
      );

      if (!isValid) {
        // 🚨 Проверяем: была ли попытка повторного использования отозванного токена
        const wasRecentlyRevoked = await this.redis.wasTokenRecentlyRevoked(
          payload.sub,
          payload.role,
          refreshToken,
        );

        if (wasRecentlyRevoked) {
          // ✅ FIX: Ещё раз проверяем кеш - возможно параллельный запрос уже обработался
          const cachedAfterRevoke = await this.redis.safeExecute(
            () => this.redis.getCachedRefreshResult(tokenHash),
            null,
            'getCachedRefreshResultAfterRevoke',
          );

          if (cachedAfterRevoke) {
            this.logger.log(`Idempotent refresh (after revoke check): returning cached tokens for ${payload.role} user`);
            return {
              success: true,
              data: cachedAfterRevoke,
            };
          }

          // SECURITY ALERT: Token reuse detected! Возможная кража токена
          // Но только если прошло больше REFRESH_GRACE_PERIOD_SECONDS
          this.logger.error(
            `🚨 SECURITY ALERT: Refresh token reuse detected for user ${payload.sub} (${payload.role}). Revoking all user tokens!`,
          );
          
          // ✅ AUDIT: Логируем критическое событие безопасности (await для критических событий)
          await this.auditService.logTokenReuse(payload.sub, payload.role, ip, userAgent);

          // Отзываем ВСЕ токены пользователя для безопасности
          await this.redis.revokeAllUserTokens(payload.sub, payload.role);

          throw new UnauthorizedException(
            'Security violation detected. All sessions have been terminated. Please login again.',
          );
        }

        throw new UnauthorizedException('Refresh token has been revoked');
      }

      // Удаляем старый refresh токен с отслеживанием (для детекции повторного использования)
      // Храним информацию об отозванном токене для детекции token reuse attack
      await this.redis.revokeRefreshTokenWithTracking(
        payload.sub,
        payload.role,
        refreshToken,
        SecurityConfig.REVOKED_TOKEN_TRACKING_TTL,
      );

      const newPayload: JwtPayload = {
        sub: payload.sub,
        login: payload.login,
        role: payload.role,
        name: payload.name,
        cities: payload.cities,
      };

      // Генерируем новую пару токенов
      const newAccessToken = this.jwtService.sign(newPayload);
      const newRefreshToken = this.jwtService.sign(newPayload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL, // ✅ FIX: Используем константу (90d)
      });

      // Сохраняем новый refresh токен в Redis
      const refreshTTL = SecurityConfig.REFRESH_TOKEN_TTL_SECONDS; // ✅ FIX: Используем константу
      await this.redis.saveRefreshToken(payload.sub, payload.role, newRefreshToken, refreshTTL);

      // ✅ FIX: Кешируем результат refresh для idempotent повторных запросов
      await this.redis.safeExecute(
        () => this.redis.cacheRefreshResult(
          tokenHash,
          newAccessToken,
          newRefreshToken,
          SecurityConfig.REFRESH_GRACE_PERIOD_SECONDS,
        ),
        undefined,
        'cacheRefreshResult',
      );

      this.logger.log(`Token refreshed for ${payload.role} user`);
      
      // ✅ FIX #12: Добавлен .catch() для обработки ошибок
      this.auditService.logTokenRefresh(payload.sub, payload.role, ip, userAgent)
        .catch(err => this.logger.error(`Audit log failed: ${err.message}`));

      return {
        success: true,
        data: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        },
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      this.logger.error('Token refresh error:', error.message);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  /**
   * ✅ FIX #11: Маппинг ролей на Prisma модели и поля для getProfile
   * Устраняет дублирование кода в switch-case
   */
  private readonly profileConfig = {
    [UserRole.ADMIN]: {
      model: 'callcentreAdmin' as const,
      select: {
        id: true, login: true, note: true, createdAt: true, updatedAt: true,
      },
    },
    [UserRole.OPERATOR]: {
      model: 'callcentreOperator' as const,
      select: {
        id: true, name: true, login: true, city: true, status: true,
        statusWork: true, dateCreate: true, note: true, sipAddress: true,
        createdAt: true, updatedAt: true,
      },
    },
    [UserRole.DIRECTOR]: {
      model: 'director' as const,
      select: {
        id: true, name: true, login: true, cities: true, dateCreate: true,
        note: true, tgId: true, createdAt: true, updatedAt: true,
      },
    },
    [UserRole.MASTER]: {
      model: 'master' as const,
      select: {
        id: true, name: true, login: true, cities: true, statusWork: true,
        dateCreate: true, note: true, tgId: true, chatId: true,
        createdAt: true, updatedAt: true,
      },
    },
  };

  /**
   * Получение профиля пользователя
   * ✅ Использует кеширование с константами из SecurityConfig
   * ✅ FIX #11: Рефакторинг через маппинг вместо switch-case
   * ✅ FIX #6: Cache Stampede Protection через distributed lock
   * ✅ Логирует обращение к профилю
   */
  async getProfile(
    user: JwtPayload, 
    ip: string = '0.0.0.0', 
    userAgent: string = 'Unknown'
  ): Promise<ProfileResponse> {
    const { sub: id, role } = user;

    // ✅ ИСПРАВЛЕНИЕ #8: Кеширование профилей в Redis с константой TTL
    const cacheKey = `profile:${role}:${id}`;

    // ✅ FIX: Оптимизированная операция - GET + SETNX за 1 round-trip
    const lockKey = `lock:${cacheKey}`;
    const LOCK_TTL = SecurityConfig.PROFILE_LOCK_TTL_SECONDS;
    const MAX_WAIT_ATTEMPTS = SecurityConfig.PROFILE_LOCK_MAX_WAIT_ATTEMPTS;
    const WAIT_INTERVAL_MS = SecurityConfig.PROFILE_LOCK_WAIT_INTERVAL_MS;
    
    // Пробуем получить из кеша И захватить lock атомарно
    const { cached, lockAcquired: acquired } = await this.redis.safeExecute(
      () => this.redis.getOrLock(cacheKey, lockKey, LOCK_TTL),
      { cached: null, lockAcquired: true }, // fallback: продолжаем без кеша
      'getOrLockProfile',
    );

    if (cached) {
      this.logger.debug(`Profile cache HIT for user ${id} (${role})`);
      
      // ✅ FIX #12: Добавлен .catch() для обработки ошибок
      this.auditService.logProfileAccess(id, role, ip, userAgent, true)
        .catch(err => this.logger.error(`Audit log failed: ${err.message}`));
      
      return {
        success: true,
        data: JSON.parse(cached) as UserProfile,
      };
    }
    
    if (!acquired) {
      // Другой запрос уже загружает профиль - ждём и проверяем кеш
      this.logger.debug(`Profile lock not acquired, waiting for cache fill for user ${id}`);
      
      for (let i = 0; i < MAX_WAIT_ATTEMPTS; i++) {
        await new Promise(resolve => setTimeout(resolve, WAIT_INTERVAL_MS));
        
        const retryCache = await this.redis.safeExecute(
          async () => {
            const value = await this.redis.get(cacheKey);
            return value ? JSON.parse(value) : null;
          },
          null,
          'retryGetProfileFromCache',
        );
        
        if (retryCache) {
          this.logger.debug(`Profile cache filled by another request for user ${id}`);
          
          this.auditService.logProfileAccess(id, role, ip, userAgent, true)
            .catch(err => this.logger.error(`Audit log failed: ${err.message}`));
          
          return {
            success: true,
            data: retryCache as UserProfile,
          };
        }
      }
      
      // Lock не освободился - продолжаем загрузку (fallback)
      this.logger.warn(`Profile lock timeout, proceeding with DB query for user ${id}`);
    }

    // Кеш промах - загружаем из БД
    this.logger.debug(`Profile cache MISS for user ${id} (${role})`);
    
    try {
      // ✅ FIX #11: Используем маппинг вместо switch-case
      const config = this.profileConfig[role];
      if (!config) {
        throw new UnauthorizedException('Invalid user role');
      }

      // ✅ Double-check кеша после получения lock
      const doubleCheckCache = await this.redis.safeExecute(
        async () => {
          const value = await this.redis.get(cacheKey);
          return value ? JSON.parse(value) : null;
        },
        null,
        'doubleCheckProfileCache',
      );
      
      if (doubleCheckCache) {
        this.logger.debug(`Profile cache filled during lock acquisition for user ${id}`);
        return {
          success: true,
          data: doubleCheckCache as UserProfile,
        };
      }

      const profile = await (this.prisma[config.model] as any).findUnique({
        where: { id },
        select: config.select,
      });

      if (!profile) {
        throw new UnauthorizedException('User profile not found');
      }

      const result: UserProfile = { ...profile, role };

      // Сохраняем в кеш (с graceful degradation)
      await this.redis.safeExecute(
        () => this.redis.set(cacheKey, JSON.stringify(result), SecurityConfig.PROFILE_CACHE_TTL),
        undefined,
        'saveProfileToCache',
      );
      
      // ✅ FIX #12: Добавлен .catch() для обработки ошибок
      this.auditService.logProfileAccess(id, role, ip, userAgent, false)
        .catch(err => this.logger.error(`Audit log failed: ${err.message}`));

      return {
        success: true,
        data: result,
      };
    } finally {
      // ✅ FIX #6: Освобождаем lock
      if (acquired) {
        await this.redis.safeExecute(
          () => this.redis.del(lockKey),
          undefined,
          'releaseProfileLock',
        );
      }
    }
  }

  /**
   * Logout пользователя - отзыв всех refresh токенов
   * ✅ Логирует событие выхода
   */
  async logout(
    user: JwtPayload, 
    ip: string = '0.0.0.0', 
    userAgent: string = 'Unknown'
  ): Promise<void> {
    const { sub: userId, role } = user;
    await this.redis.revokeAllUserTokens(userId, role);
    this.logger.log(`User logged out: ${role} user`);
    
    // ✅ FIX #12: Добавлен .catch() для обработки ошибок
    this.auditService.logLogout(userId, role, ip, userAgent)
      .catch(err => this.logger.error(`Audit log failed: ${err.message}`));
  }

  /**
   * Принудительная деавторизация пользователя (админ-функция)
   * ✅ Удаляет все refresh токены
   * ✅ Устанавливает флаг force_logout для мгновенной блокировки access токенов
   * @param userId ID пользователя для деавторизации
   * @param role Роль пользователя (валидируется через UserRole enum)
   * @param adminId ID администратора, выполняющего действие
   * @param adminRole Роль администратора
   * @param ip IP адрес администратора
   * @param userAgent User-Agent администратора
   */
  async forceLogout(
    userId: number,
    role: UserRole,  // ✅ FIX: Используем enum вместо string
    adminId: number,
    adminRole: UserRole,  // ✅ FIX: Используем enum вместо string
    ip: string = '0.0.0.0',
    userAgent: string = 'Unknown',
  ): Promise<void> {
    // 1. Удаляем все refresh токены
    await this.redis.revokeAllUserTokens(userId, role);
    
    // 2. Устанавливаем флаг принудительной деавторизации (действует как TTL access token)
    await this.redis.forceLogoutUser(userId, role, SecurityConfig.FORCE_LOGOUT_TTL_SECONDS);
    
    this.logger.warn(
      `🔒 Force logout: ${role} user #${userId} by admin #${adminId} (${adminRole})`,
    );
    
    // ✅ FIX #12: Добавлен .catch() для обработки ошибок
    this.auditService.logForceLogout(userId, role, adminId, adminRole, ip, userAgent)
      .catch(err => this.logger.error(`Audit log failed: ${err.message}`));
  }
}
