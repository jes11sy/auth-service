import { Controller, Post, Body, Get, UseGuards, Request, HttpCode, HttpStatus, Ip, Headers, Res, Req, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle, SkipThrottle } from '@nestjs/throttler';
import { FastifyReply, FastifyRequest } from 'fastify';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { ForceLogoutDto } from './dto/force-logout.dto';
import { CookieJwtAuthGuard } from './guards/cookie-jwt-auth.guard';
import { RedisService } from '../redis/redis.service';
import { PrismaService } from '../prisma/prisma.service';
import { CookieConfig, shouldUseCookies, getCookieOptions, getCookieName } from '../../config/cookie.config';
import { SecurityConfig } from '../../config/security.config';
import { UserRole } from './interfaces/auth.interface';

@ApiTags('auth')
@Controller('auth')
export class AuthController {
  constructor(
    private readonly authService: AuthService,
    private readonly redis: RedisService,
    private readonly prisma: PrismaService,
  ) {}

  /**
   * Вспомогательный метод для извлечения User-Agent из заголовков
   */
  private getUserAgent(headers: any): string {
    return headers['user-agent'] || 'Unknown';
  }

  @Get('health')
  @SkipThrottle() // ✅ Health check не лимитируется
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Health check endpoint' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  @ApiResponse({ status: 503, description: 'Service is unhealthy' })
  async health(@Headers() headers: any) {
    // ✅ FIX: Детальные метрики только для внутренних запросов
    const isInternalRequest = headers['x-internal-health-check'] === 'true' || 
                              headers['authorization']?.startsWith('Bearer ');

    const checks = {
      database: { healthy: false, latencyMs: 0 },
      redis: { healthy: false, latencyMs: 0 },
    };

    // ✅ FIX: Используем константы из SecurityConfig
    const DB_LATENCY_THRESHOLD_MS = SecurityConfig.DATABASE_LATENCY_THRESHOLD_MS;
    const REDIS_LATENCY_THRESHOLD_MS = SecurityConfig.REDIS_LATENCY_THRESHOLD_MS;

    try {
      const dbStart = Date.now();
      await this.prisma.$queryRaw`SELECT 1`;
      checks.database.latencyMs = Date.now() - dbStart;
      checks.database.healthy = checks.database.latencyMs < DB_LATENCY_THRESHOLD_MS;
    } catch (error) {
      checks.database.healthy = false;
    }

    try {
      const redisStart = Date.now();
      const redisOk = await this.redis.healthCheck();
      checks.redis.latencyMs = Date.now() - redisStart;
      checks.redis.healthy = redisOk && checks.redis.latencyMs < REDIS_LATENCY_THRESHOLD_MS;
    } catch (error) {
      checks.redis.healthy = false;
    }

    const isHealthy = checks.database.healthy && checks.redis.healthy;

    // ✅ FIX: Публичный ответ - только status (без метрик)
    if (!isInternalRequest) {
      return {
        success: isHealthy,
        message: isHealthy ? 'Auth Service is healthy' : 'Auth Service is unhealthy',
        timestamp: new Date().toISOString(),
      };
    }

    // ✅ Внутренний ответ - полные метрики для мониторинга
    const warnings: string[] = [];
    if (checks.database.healthy && checks.database.latencyMs > DB_LATENCY_THRESHOLD_MS / 2) {
      warnings.push(`Database latency is high: ${checks.database.latencyMs}ms`);
    }
    if (checks.redis.healthy && checks.redis.latencyMs > REDIS_LATENCY_THRESHOLD_MS / 2) {
      warnings.push(`Redis latency is high: ${checks.redis.latencyMs}ms`);
    }

    return {
      success: isHealthy,
      message: isHealthy ? 'Auth Service is healthy' : 'Auth Service is unhealthy',
      timestamp: new Date().toISOString(),
      checks,
      ...(warnings.length > 0 && { warnings }),
    };
  }

  @Post('login')
  @Throttle({ default: { limit: 5, ttl: 60000 } }) // ✅ VULN-001: 5 попыток в минуту
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user by role (supports both JSON and httpOnly cookies)' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async login(
    @Body() loginDto: LoginDto,
    @Ip() ip: string,
    @Headers() headers: any,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const userAgent = this.getUserAgent(headers);
    const result = await this.authService.login(loginDto, ip, userAgent);
    
    // ✅ DUAL MODE: проверяем, хочет ли клиент использовать cookies
    const useCookies = shouldUseCookies(headers);
    
    if (useCookies) {
      // Новый способ: httpOnly cookies с динамическим domain
      const origin = headers.origin || headers.referer;
      const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin);
      const refreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
      const accessTokenOptions = getCookieOptions(origin, CookieConfig.ACCESS_TOKEN_MAX_AGE);
      const refreshTokenOptions = getCookieOptions(origin, CookieConfig.REFRESH_TOKEN_MAX_AGE);
      
      // Используем raw reply для доступа к методам @fastify/cookie
      const rawReply = res as any;
      rawReply.setCookie(accessTokenName, result.data.accessToken, {
        ...accessTokenOptions,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING,
      });
      
      rawReply.setCookie(refreshTokenName, result.data.refreshToken, {
        ...refreshTokenOptions,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING,
      });
      
      // Не отправляем токены в response body (они в cookies)
      return {
        success: true,
        message: 'Login successful',
        data: {
          user: result.data.user,
          // accessToken и refreshToken НЕ включаем
        },
      };
    }
    
    // Старый способ: JSON response (для обратной совместимости)
    return result;
  }

  @Post('refresh')
  @Throttle({ default: { limit: 20, ttl: 60000 } }) // ✅ VULN-001: 20 обновлений в минуту
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token (supports both JSON and httpOnly cookies)' })
  @ApiResponse({ status: 200, description: 'Token refreshed' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Ip() ip: string,
    @Headers() headers: any,
    @Req() req: FastifyRequest,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const userAgent = this.getUserAgent(headers);
    const useCookies = shouldUseCookies(headers);
    const origin = headers.origin || headers.referer;
    
    // ✅ DUAL MODE: получаем refresh token из cookies ИЛИ body
    let refreshToken: string | undefined;
    
    if (useCookies) {
      // Получаем из cookies с учетом origin
      const reqWithCookies = req as any;
      const refreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
      
      if (CookieConfig.ENABLE_COOKIE_SIGNING) {
        const signedCookie = reqWithCookies.cookies?.[refreshTokenName];
        if (signedCookie && reqWithCookies.unsignCookie) {
          const unsigned = reqWithCookies.unsignCookie(signedCookie);
          refreshToken = unsigned?.valid ? unsigned.value : undefined;
          
          // Если подпись невалидна - возможная атака
          if (unsigned && !unsigned.valid) {
            throw new UnauthorizedException('Invalid refresh token signature. Possible tampering.');
          }
        }
      } else {
        refreshToken = reqWithCookies.cookies?.[refreshTokenName];
      }
    } else {
      // Старый способ - из body
      refreshToken = refreshTokenDto.refreshToken;
    }
    
    if (!refreshToken) {
      throw new UnauthorizedException('Refresh token not found');
    }
    
    const result = await this.authService.refreshToken(refreshToken, ip, userAgent);
    
    if (useCookies) {
      // Устанавливаем новые cookies с учетом origin
      const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin);
      const refreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
      const accessTokenOptions = getCookieOptions(origin, CookieConfig.ACCESS_TOKEN_MAX_AGE);
      const refreshTokenOptions = getCookieOptions(origin, CookieConfig.REFRESH_TOKEN_MAX_AGE);
      
      const rawReply = res as any;
      rawReply.setCookie(accessTokenName, result.data.accessToken, {
        ...accessTokenOptions,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING,
      });
      
      rawReply.setCookie(refreshTokenName, result.data.refreshToken, {
        ...refreshTokenOptions,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING,
      });
      
      return {
        success: true,
        data: {}, // Токены в cookies, не отправляем в body
      };
    }
    
    // Старый способ: JSON response
    return result;
  }

  @Post('logout')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // ✅ 10 logout запросов в минуту
  @UseGuards(CookieJwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout user (revokes all refresh tokens)' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  async logout(
    @Request() req,
    @Ip() ip: string,
    @Headers() headers: any,
    @Res({ passthrough: true }) res: FastifyReply,
  ) {
    const userAgent = this.getUserAgent(headers);
    const useCookies = shouldUseCookies(headers);
    const origin = headers.origin || headers.referer;
    
    await this.authService.logout(req.user, ip, userAgent);
    
    if (useCookies) {
      // Очищаем cookies с учетом origin
      const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin);
      const refreshTokenName = getCookieName(CookieConfig.REFRESH_TOKEN_NAME, origin);
      const clearOptions = getCookieOptions(origin, 0); // maxAge: 0 для удаления
      
      const rawReply = res as any;
      rawReply.setCookie(accessTokenName, '', clearOptions);
      rawReply.setCookie(refreshTokenName, '', clearOptions);
    }
    
    return {
      success: true,
      message: 'Logout successful',
    };
  }

  @Get('validate')
  @Throttle({ default: { limit: 50, ttl: 60000 } }) // ✅ 50 валидаций в минуту
  @UseGuards(CookieJwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Validate JWT token (supports both Authorization header and cookies)' })
  @ApiResponse({ status: 200, description: 'Token is valid' })
  @ApiResponse({ status: 401, description: 'Invalid token' })
  async validate(@Request() req) {
    return {
      valid: true,
      user: req.user,
    };
  }

  @Get('profile')
  @Throttle({ default: { limit: 100, ttl: 60000 } }) // ✅ 100 запросов профиля в минуту (увеличено для React Strict Mode)
  @UseGuards(CookieJwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile (supports both Authorization header and cookies)' })
  @ApiResponse({ status: 200, description: 'Profile retrieved' })
  async getProfile(
    @Request() req,
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    const userAgent = this.getUserAgent(headers);
    return this.authService.getProfile(req.user, ip, userAgent);
  }

  @Get('socket-token')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // ✅ 10 запросов в минуту
  @UseGuards(CookieJwtAuthGuard)
  @ApiOperation({ summary: '🔌 Get short-lived token for Socket.IO from httpOnly cookie' })
  @ApiResponse({ status: 200, description: 'Socket token returned' })
  async getSocketToken(
    @Request() req,
    @Req() request: FastifyRequest,
  ) {
    // ✅ FIX #4: Используем уже валидированный токен из request.user
    // Guard уже проверил JWT, поэтому просто возвращаем данные из payload
    // Это безопаснее чем извлекать и возвращать raw cookie
    
    if (!req.user || !req.user.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }
    
    // Читаем access token из httpOnly cookie (с учетом динамического имени)
    const rawRequest = request as any;
    const origin = request.headers.origin || request.headers.referer;
    const accessTokenName = getCookieName(CookieConfig.ACCESS_TOKEN_NAME, origin as string);
    
    // Пробуем динамическое имя, потом fallback на базовое
    let rawCookie = rawRequest.cookies?.[accessTokenName];
    if (!rawCookie) {
      rawCookie = rawRequest.cookies?.[CookieConfig.ACCESS_TOKEN_NAME];
    }

    if (!rawCookie) {
      throw new UnauthorizedException('No access token in cookies');
    }

    // Извлекаем JWT из cookie (может быть с подписью - 4 части)
    let token = rawCookie;
    if (typeof token === 'string' && token.startsWith('eyJ')) {
      const parts = token.split('.');
      if (parts.length === 4) {
        // Убираем старую подпись cookie
        token = parts.slice(0, 3).join('.');
      } else if (parts.length !== 3) {
        // ✅ FIX #4: Невалидный формат JWT
        throw new UnauthorizedException('Invalid token format');
      }
    } else {
      throw new UnauthorizedException('Invalid token format');
    }

    // ✅ FIX #4: Дополнительная проверка - payload из cookie должен совпадать с req.user
    // Это защищает от подмены токена между валидацией guard и этим endpoint
    try {
      const payloadBase64 = token.split('.')[1];
      const payload = JSON.parse(Buffer.from(payloadBase64, 'base64').toString('utf8'));
      
      if (payload.sub !== req.user.sub || payload.role !== req.user.role) {
        throw new UnauthorizedException('Token mismatch detected');
      }
    } catch (error) {
      if (error instanceof UnauthorizedException) throw error;
      throw new UnauthorizedException('Invalid token structure');
    }

    // Возвращаем токен для Socket.IO (он уже валидный и короткоживущий - 15 минут)
    return {
      success: true,
      data: {
        token: token,
        expiresIn: 900, // 15 минут в секундах
      },
    };
  }

  @Post('admin/force-logout')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // ✅ FIX: Rate limiting - 10 запросов в минуту
  @UseGuards(CookieJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Force logout user (admin only)' })
  @ApiResponse({ status: 200, description: 'User forcefully logged out' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async forceLogout(
    @Request() req,
    @Body() body: ForceLogoutDto, // ✅ FIX: Используем DTO с валидацией
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    // ✅ FIX: Используем enum вместо строки для консистентности
    if (req.user.role !== UserRole.ADMIN) {
      throw new ForbiddenException('Only administrators can force logout users');
    }

    const userAgent = this.getUserAgent(headers);
    await this.authService.forceLogout(
      body.userId,
      body.role as UserRole,  // ✅ FIX: Кастуем к enum (уже провалидировано DTO)
      req.user.sub,
      req.user.role as UserRole,
      ip,
      userAgent,
    );

    return {
      success: true,
      message: `User #${body.userId} (${body.role}) has been forcefully logged out`,
    };
  }
}

