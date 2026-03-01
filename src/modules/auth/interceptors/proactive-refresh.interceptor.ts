import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  Logger,
} from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap } from 'rxjs/operators';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { CookieConfig, shouldUseCookies, setCookies, getCookieName } from '../../../config/cookie.config';
import { RedisService } from '../../redis/redis.service';
import { SecurityConfig } from '../../../config/security.config';

/**
 * 🔄 Проактивное обновление токена
 * Если токен скоро истечёт (меньше 5 минут), автоматически обновляем его
 * Работает прозрачно для клиента — новые токены отправляются в response cookies
 * 
 * ✅ ИСПРАВЛЕНО: Использует правильный JWT_REFRESH_SECRET
 * ✅ ИСПРАВЛЕНО: Сохраняет refresh токен в Redis
 */
@Injectable()
export class ProactiveRefreshInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ProactiveRefreshInterceptor.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly redis: RedisService,
  ) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    return next.handle().pipe(
      tap(async () => {
        // Проверяем, нужно ли проактивное обновление
        if (request.__needsProactiveRefresh && request.user) {
          const useCookies = shouldUseCookies(request.headers);
          
          if (useCookies) {
            try {
              // Генерируем новые токены
              const payload = {
                sub: request.user.sub || request.user.userId,
                login: request.user.login,
                role: request.user.role,
                name: request.user.name,
                cityIds: request.user.cityIds,
              };

              // ✅ ИСПРАВЛЕНИЕ: Используем JWT_SECRET для access token
              const newAccessToken = this.jwtService.sign(payload);
              
              // ✅ FIX #1: Используем константу из SecurityConfig вместо hardcoded '7d'
              const newRefreshToken = this.jwtService.sign(payload, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
                expiresIn: SecurityConfig.REFRESH_TOKEN_DEFAULT_TTL, // '90d'
              });

              // ✅ FIX #2: Отзываем старый refresh токен перед сохранением нового
              const origin = request.headers.origin || request.headers.referer;
              const oldRefreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
              const cookies = (request as any).cookies || {};
              let oldRefreshToken = cookies[oldRefreshTokenName];
              
              // ✅ FIX #3: Также проверяем базовое имя cookie (fallback)
              if (!oldRefreshToken) {
                oldRefreshToken = cookies[CookieConfig.REFRESH_TOKEN_NAME];
              }
              
              if (oldRefreshToken && typeof oldRefreshToken === 'string') {
                // ✅ FIX: Извлекаем чистый JWT если это signed cookie (4 части)
                let cleanToken = oldRefreshToken;
                if (oldRefreshToken.startsWith('eyJ')) {
                  const parts = oldRefreshToken.split('.');
                  if (parts.length === 4) {
                    // JWT + cookie signature - берём только JWT (первые 3 части)
                    cleanToken = parts.slice(0, 3).join('.');
                  }
                }
                
                // Отзываем старый токен с отслеживанием для детекции token reuse
                await this.redis.revokeRefreshTokenWithTracking(
                  payload.sub,
                  payload.role,
                  cleanToken,
                  SecurityConfig.REVOKED_TOKEN_TRACKING_TTL,
                );
              }

              // ✅ FIX #1: Используем константу TTL из SecurityConfig
              const refreshTTL = SecurityConfig.REFRESH_TOKEN_TTL_SECONDS;
              await this.redis.saveRefreshToken(
                payload.sub,
                payload.role,
                newRefreshToken,
                refreshTTL,
              );

              // Устанавливаем новые токены в cookies
              setCookies(response, newAccessToken, newRefreshToken, origin);

              this.logger.debug(
                `🔄 Proactively refreshed tokens for user ${payload.sub} (${payload.role})`,
              );
            } catch (error) {
              // Не ломаем запрос если обновление не удалось
              this.logger.warn(`Failed to proactively refresh token: ${error.message}`);
            }
          }
        }
      }),
    );
  }
}

