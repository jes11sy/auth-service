import { Injectable, ExecutionContext, UnauthorizedException, Inject } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { CookieConfig } from '../../../config/cookie.config';
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
 */
@Injectable()
export class CookieJwtAuthGuard extends JwtAuthGuard {
  constructor(
    @Inject(RedisService) private readonly redis: RedisService,
  ) {
    super();
  }
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    
    // В NestJS + Fastify cookies находятся в request.cookies
    const cookies = (request as any).cookies || (request.raw as any)?.cookies || null;
    
    let cookieToken: string | null = null;
    
    if (cookies) {
      const rawCookie = cookies[CookieConfig.ACCESS_TOKEN_NAME];
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

