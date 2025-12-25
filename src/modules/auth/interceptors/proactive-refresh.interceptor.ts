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
import { CookieConfig, shouldUseCookies, setCookies } from '../../../config/cookie.config';

/**
 * 🔄 Проактивное обновление токена
 * Если токен скоро истечёт (меньше 5 минут), автоматически обновляем его
 * Работает прозрачно для клиента — новые токены отправляются в response cookies
 */
@Injectable()
export class ProactiveRefreshInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ProactiveRefreshInterceptor.name);

  constructor(private readonly jwtService: JwtService) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const request = context.switchToHttp().getRequest();
    const response = context.switchToHttp().getResponse();

    return next.handle().pipe(
      tap(() => {
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

              const newAccessToken = this.jwtService.sign(payload);
              const newRefreshToken = this.jwtService.sign(payload, {
                expiresIn: '7d', // 🔒 Захардкожено: Refresh token живёт 7 дней
              });

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

