import { Injectable, ExecutionContext, UnauthorizedException, Inject, Logger } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { CookieConfig, getCookieName } from '../../../config/cookie.config';
import { RedisService } from '../../redis/redis.service';

/**
 * Guard для поддержки JWT токенов из cookies
 * Расширяет стандартный JwtAuthGuard, добавляя поддержку извлечения токенов из httpOnly cookies
 * 
 * Приоритет извлечения токена:
 * 1. Authorization header (Bearer token) - для обратной совместимости
 * 2. Cookie access_token - новый способ (httpOnly)
 * 
 * ✅ Проверяет флаг принудительной деавторизации (force_logout)
 * ✅ Проактивное обновление токена если осталось меньше 5 минут до истечения
 */
@Injectable()
export class CookieJwtAuthGuard extends JwtAuthGuard {
  private readonly logger = new Logger(CookieJwtAuthGuard.name);
  
  constructor(
    @Inject(RedisService) private readonly redis: RedisService,
  ) {
    super();
  }
  
  /**
   * Декодирует JWT токен (без верификации) для получения payload
   */
  private decodeJwt(token: string): any {
    try {
      const parts = token.split('.');
      if (parts.length !== 3) return null;
      
      const payload = Buffer.from(parts[1], 'base64').toString('utf8');
      return JSON.parse(payload);
    } catch {
      return null;
    }
  }
  
  /**
   * Проверяет, нужно ли проактивно обновить токен
   * @returns true если до истечения осталось меньше 5 минут
   */
  private shouldProactivelyRefresh(token: string): boolean {
    const payload = this.decodeJwt(token);
    if (!payload || !payload.exp) return false;
    
    const expiresAt = payload.exp * 1000; // переводим в миллисекунды
    const now = Date.now();
    const timeLeft = expiresAt - now;
    
    // Обновляем если осталось меньше 5 минут (300 секунд)
    const REFRESH_THRESHOLD = 5 * 60 * 1000;
    
    return timeLeft > 0 && timeLeft < REFRESH_THRESHOLD;
  }
  
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // В NestJS + Fastify cookies находятся в request.cookies
    const cookies = (request as any).cookies || (request.raw as any)?.cookies || null;
    
    let cookieToken: string | null = null;
    
    if (cookies) {
      // Определяем имя cookie на основе origin
      const origin = request.headers.origin || request.headers.referer;
      const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin);
      
      // Пробуем получить токен с динамическим именем (новый способ)
      let rawCookie = cookies[accessTokenName];
      
      // Fallback: если не нашли, пробуем базовое имя (для обратной совместимости)
      if (!rawCookie) {
        rawCookie = cookies[CookieConfig.ACCESS_TOKEN_NAME];
      }
      
      if (rawCookie && rawCookie.startsWith('eyJ')) {
        // ✅ JWT токен найден
        const parts = rawCookie.split('.');
        
        if (parts.length === 3) {
          // Стандартный JWT (header.payload.signature)
          cookieToken = rawCookie;
        } else if (parts.length === 4) {
          // JWT + старая подпись cookie (миграция с signed cookies)
          // Берём только первые 3 части
          cookieToken = parts.slice(0, 3).join('.');
        }
        
        // 🔄 ПРОАКТИВНОЕ ОБНОВЛЕНИЕ: помечаем запрос если нужен refresh
        if (cookieToken && this.shouldProactivelyRefresh(cookieToken)) {
          this.logger.debug(`🔄 Token expires soon, marking for proactive refresh`);
          request.__needsProactiveRefresh = true;
        }
      }
    }
    
    // Если токен в cookie есть и нет Authorization header - используем cookie
    if (cookieToken && !request.headers.authorization) {
      request.headers.authorization = `Bearer ${cookieToken}`;
    }
    
    // Вызываем родительский guard для валидации токена
    return super.canActivate(context);
  }
  
  /**
   * Обработка ошибок с понятными сообщениями
   * ✅ Проверяет флаг принудительной деавторизации
   */
  async handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      if (info?.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Access token has expired. Please refresh your token.');
      }
      if (info?.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid access token.');
      }
      throw err || new UnauthorizedException('Authentication required.');
    }

    // ✅ FORCE LOGOUT CHECK: Проверяем флаг принудительной деавторизации
    if (user.sub && user.role) {
      try {
        const isForcedLogout = await this.redis.isUserForcedLogout(user.sub, user.role);
        if (isForcedLogout) {
          throw new UnauthorizedException('Session terminated by administrator. Please login again.');
        }
      } catch (error) {
        // Graceful degradation: если Redis недоступен, пропускаем проверку
        // Не блокируем пользователя если инфраструктура временно недоступна
        if (error instanceof UnauthorizedException) {
          throw error;
        }
        // Логируем ошибку, но продолжаем работу
        console.warn('Force logout check failed (Redis unavailable):', error.message);
      }
    }

    return user;
  }
}

