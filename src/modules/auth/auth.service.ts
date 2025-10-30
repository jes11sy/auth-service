import { Injectable, UnauthorizedException, Logger, ForbiddenException } from '@nestjs/common';
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
export class AuthService {
  private readonly logger = new Logger(AuthService.name);
  private dummyHash: string;

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
    private auditService: AuditService,
  ) {
    // ✅ ИСПРАВЛЕНИЕ: Генерируем dummy hash при старте сервиса
    // Используется для защиты от timing attack
    this.initializeDummyHash();
  }

  /**
   * Генерация dummy hash для защиты от timing attack
   * Выполняется один раз при инициализации сервиса
   */
  private async initializeDummyHash(): Promise<void> {
    try {
      // Генерируем случайный dummy hash с уникальным seed
      const randomSeed = `dummy_${Date.now()}_${Math.random()}`;
      this.dummyHash = await bcrypt.hash(randomSeed, SecurityConfig.BCRYPT_ROUNDS);
      this.logger.log('✅ Dummy hash initialized for timing attack protection');
    } catch (error) {
      // Fallback на статичный hash если генерация не удалась
      this.dummyHash = '$2a$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LewY5GyYzNGJ3zHHO';
      this.logger.warn('⚠️ Using fallback dummy hash due to initialization error');
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
      // Загружаем пользователя в зависимости от роли
      switch (role as UserRole) {
        case UserRole.ADMIN:
          user = await this.prisma.callcentreAdmin.findUnique({
            where: { login },
          });
          break;

        case UserRole.OPERATOR:
          user = await this.prisma.callcentreOperator.findUnique({
            where: { login },
          });
          break;

        case UserRole.DIRECTOR:
          user = await this.prisma.director.findUnique({
            where: { login },
          });
          break;

        case UserRole.MASTER:
          user = await this.prisma.master.findUnique({
            where: { login },
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

    // ✅ ИСПРАВЛЕНИЕ #13: Graceful degradation - если Redis недоступен, продолжаем без brute-force защиты
    const lockIdentifier = `${login}:${role}`;
    
    const isLocked = await this.redis.safeExecute(
      () => this.redis.isAccountLocked(lockIdentifier, SecurityConfig.MAX_LOGIN_ATTEMPTS),
      false, // fallback: не блокируем если Redis недоступен
      'isAccountLocked',
    );

    if (isLocked) {
      const ttl = await this.redis.getLockTTL(lockIdentifier);
      const minutesLeft = secondsToMinutes(ttl);
      this.logger.warn(`Account locked: ${role} user (attempts exceeded)`);
      
      // ✅ AUDIT: Логируем блокировку аккаунта
      this.auditService.logLoginBlocked(login, role as UserRole, ip, userAgent, minutesLeft);
      
      throw new ForbiddenException(
        `Too many login attempts. Try again in ${minutesLeft} minute(s).`,
      );
    }

    const user = await this.validateUser(login, password, role);

    if (!user) {
      // Записываем неудачную попытку (с graceful degradation)
      const attempts = await this.redis.safeExecute(
        () => this.redis.recordLoginAttempt(lockIdentifier),
        0, // fallback: 0 попыток если Redis недоступен
        'recordLoginAttempt',
      );
      const remainingAttempts = SecurityConfig.MAX_LOGIN_ATTEMPTS - attempts;
      
      this.logger.warn(`Failed login attempt for ${role} user (${attempts}/${SecurityConfig.MAX_LOGIN_ATTEMPTS} attempts)`);
      
      // ✅ AUDIT: Логируем неудачную попытку входа
      this.auditService.logLoginFailed(
        login, 
        role as UserRole, 
        ip, 
        userAgent, 
        'Invalid credentials',
        attempts,
      );
      
      if (remainingAttempts > 0 && attempts > 0) {
        throw new UnauthorizedException(
          `Invalid credentials. ${remainingAttempts} attempt(s) remaining.`,
        );
      } else if (attempts >= SecurityConfig.MAX_LOGIN_ATTEMPTS) {
        throw new ForbiddenException(
          `Too many failed login attempts. Account locked for ${SecurityConfig.LOGIN_LOCK_DURATION_SECONDS / SecurityConfig.SECONDS_PER_MINUTE} minutes.`,
        );
      } else {
        // Redis недоступен - просто возвращаем базовую ошибку
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
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION', SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL),
    });

    // ✅ ИСПРАВЛЕНИЕ #12: Redis Pipelining - сохраняем токен И сбрасываем attempts за 1 round trip
    const refreshExpirationStr = this.configService.get<string>('JWT_REFRESH_EXPIRATION', SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL);
    const refreshTTL = parseExpirationToSeconds(refreshExpirationStr);
    
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

    this.logger.log(`Login successful for ${role} user`);
    
    // ✅ AUDIT: Логируем успешный вход
    this.auditService.logLoginSuccess(user.id, user.role, user.login, ip, userAgent);

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
   */
  async refreshToken(
    refreshToken: string, 
    ip: string = '0.0.0.0', 
    userAgent: string = 'Unknown'
  ): Promise<RefreshTokenResponse> {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      }) as JwtPayload;

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
          // SECURITY ALERT: Token reuse detected! Возможная кража токена
          this.logger.error(
            `🚨 SECURITY ALERT: Refresh token reuse detected for user ${payload.sub} (${payload.role}). Revoking all user tokens!`,
          );
          
          // ✅ AUDIT: Логируем критическое событие безопасности
          this.auditService.logTokenReuse(payload.sub, payload.role, ip, userAgent);

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
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION', SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL),
      });

      // Сохраняем новый refresh токен в Redis
      const refreshExpirationStr = this.configService.get<string>('JWT_REFRESH_EXPIRATION', SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL);
      const refreshTTL = parseExpirationToSeconds(refreshExpirationStr);
      await this.redis.saveRefreshToken(payload.sub, payload.role, newRefreshToken, refreshTTL);

      this.logger.log(`Token refreshed for ${payload.role} user`);
      
      // ✅ AUDIT: Логируем обновление токена
      this.auditService.logTokenRefresh(payload.sub, payload.role, ip, userAgent);

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
   * Получение профиля пользователя
   * ✅ Использует кеширование с константами из SecurityConfig
   * ✅ Строгая типизация
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

    // Пробуем получить из кеша
    const cached = await this.redis.safeExecute(
      async () => {
        const value = await this.redis.get(cacheKey);
        return value ? JSON.parse(value) : null;
      },
      null,
      'getProfileFromCache',
    );

    if (cached) {
      this.logger.debug(`Profile cache HIT for user ${id} (${role})`);
      
      // ✅ AUDIT: Логируем доступ к профилю (cache hit)
      this.auditService.logProfileAccess(id, role, ip, userAgent, true);
      
      return {
        success: true,
        data: cached as UserProfile,
      };
    }

    // Кеш промах - загружаем из БД
    this.logger.debug(`Profile cache MISS for user ${id} (${role})`);
    let profile: any = null;

    switch (role) {
      case UserRole.ADMIN:
        profile = await this.prisma.callcentreAdmin.findUnique({
          where: { id },
          select: {
            id: true,
            login: true,
            note: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case UserRole.OPERATOR:
        profile = await this.prisma.callcentreOperator.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            city: true,
            status: true,
            statusWork: true,
            dateCreate: true,
            note: true,
            sipAddress: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case UserRole.DIRECTOR:
        profile = await this.prisma.director.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            cities: true,
            dateCreate: true,
            note: true,
            tgId: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case UserRole.MASTER:
        profile = await this.prisma.master.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            cities: true,
            statusWork: true,
            dateCreate: true,
            note: true,
            tgId: true,
            chatId: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;
    }

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
    
    // ✅ AUDIT: Логируем доступ к профилю (cache miss)
    this.auditService.logProfileAccess(id, role, ip, userAgent, false);

    return {
      success: true,
      data: result,
    };
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
    
    // ✅ AUDIT: Логируем выход из системы
    this.auditService.logLogout(userId, role, ip, userAgent);
  }
}
