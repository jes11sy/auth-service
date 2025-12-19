import { Injectable, ExecutionContext, UnauthorizedException } from '@nestjs/common';
import { JwtAuthGuard } from './jwt-auth.guard';
import { CookieConfig } from '../../../config/cookie.config';

/**
 * Guard для поддержки JWT токенов из cookies
 * Расширяет стандартный JwtAuthGuard, добавляя поддержку извлечения токенов из httpOnly cookies
 * 
 * Приоритет извлечения токена:
 * 1. Authorization header (Bearer token) - для обратной совместимости
 * 2. Cookie access_token - новый способ (httpOnly)
 */
@Injectable()
export class CookieJwtAuthGuard extends JwtAuthGuard {
  canActivate(context: ExecutionContext) {
    const request = context.switchToHttp().getRequest();
    const rawRequest = request.raw as any;
    
    // ✅ ВАЖНО: В NestJS + Fastify cookies находятся в request.cookies, а НЕ rawRequest.cookies
    const cookies = (request as any).cookies || rawRequest.cookies || null;
    const unsignCookie = (request as any).unsignCookie || rawRequest.unsignCookie || null;
    
    let cookieToken = null;
    
    if (cookies && CookieConfig.ENABLE_COOKIE_SIGNING && unsignCookie) {
      // Пытаемся получить подписанный cookie (защита от tampering)
      const signedCookie = cookies[CookieConfig.ACCESS_TOKEN_NAME];
      if (signedCookie) {
        const unsigned = unsignCookie(signedCookie);
        cookieToken = unsigned?.valid ? unsigned.value : null;
        
        // Если подпись не валидна
        if (unsigned && !unsigned.valid) {
          throw new UnauthorizedException('Invalid cookie signature detected. Possible tampering attempt.');
        }
      }
    } else if (cookies) {
      // Fallback на обычные cookies если signing отключен
      cookieToken = cookies[CookieConfig.ACCESS_TOKEN_NAME];
    }
    
    // Если токен в cookie есть и нет Authorization header - используем cookie
    if (cookieToken && !request.headers.authorization) {
      // Добавляем токен из cookie в заголовок для JWT strategy
      request.headers.authorization = `Bearer ${cookieToken}`;
    }
    
    // Вызываем родительский guard для валидации токена
    return super.canActivate(context);
  }
  
  /**
   * Обработка ошибок с понятными сообщениями
   */
  handleRequest(err: any, user: any, info: any) {
    if (err || !user) {
      if (info?.name === 'TokenExpiredError') {
        throw new UnauthorizedException('Access token has expired. Please refresh your token.');
      }
      if (info?.name === 'JsonWebTokenError') {
        throw new UnauthorizedException('Invalid access token.');
      }
      throw err || new UnauthorizedException('Authentication required.');
    }
    return user;
  }
}

