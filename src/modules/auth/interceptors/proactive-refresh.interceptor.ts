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
import { CookieConfig, shouldUseCookies, setCookies } from '../../../config/cookie.config';
import { RedisService } from '../../redis/redis.service';

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
                cities: request.user.cities,
              };

              // ✅ ИСПРАВЛЕНИЕ: Используем JWT_SECRET для access token
              const newAccessToken = this.jwtService.sign(payload);
              
              // ✅ ИСПРАВЛЕНИЕ: Используем JWT_REFRESH_SECRET для refresh token
              const newRefreshToken = this.jwtService.sign(payload, {
                secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
                expiresIn: '7d', // 🔒 Захардкожено: Refresh token живёт 7 дней
              });

              // ✅ ИСПРАВЛЕНИЕ: Сохраняем новый refresh токен в Redis
              const refreshTTL = 7 * 24 * 60 * 60; // 7 дней в секундах
              await this.redis.saveRefreshToken(
                payload.sub,
                payload.role,
                newRefreshToken,
                refreshTTL,
              );

              // Устанавливаем новые токены в cookies
              const origin = request.headers.origin || request.headers.referer;
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

