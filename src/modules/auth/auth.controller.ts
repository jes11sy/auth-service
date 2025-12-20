import { Controller, Post, Body, Get, UseGuards, Request, HttpCode, HttpStatus, Ip, Headers, Res, Req, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle, SkipThrottle } from '@nestjs/throttler';
import { FastifyReply, FastifyRequest } from 'fastify';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { CookieJwtAuthGuard } from './guards/cookie-jwt-auth.guard';
import { RedisService } from '../redis/redis.service';
import { PrismaService } from '../prisma/prisma.service';
import { CookieConfig, shouldUseCookies } from '../../config/cookie.config';

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
  async health() {
    const checks = {
      database: false,
      redis: false,
    };

    try {
      // Проверка БД
      await this.prisma.$queryRaw`SELECT 1`;
      checks.database = true;
    } catch (error) {
      // БД недоступна
    }

    try {
      // Проверка Redis
      checks.redis = await this.redis.healthCheck();
    } catch (error) {
      // Redis недоступен
    }

    const isHealthy = checks.database && checks.redis;

    return {
      success: isHealthy,
      message: isHealthy ? 'Auth Service is healthy' : 'Auth Service is unhealthy',
      timestamp: new Date().toISOString(),
      checks,
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
      // Новый способ: httpOnly cookies с подписью
      // Используем raw reply для доступа к методам @fastify/cookie
      const rawReply = res as any;
      rawReply.setCookie(CookieConfig.ACCESS_TOKEN_NAME, result.data.accessToken, {
        ...CookieConfig.COOKIE_OPTIONS,
        maxAge: CookieConfig.ACCESS_TOKEN_MAX_AGE,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING, // ✅ Подписанный cookie
      });
      
      rawReply.setCookie(CookieConfig.REFRESH_TOKEN_NAME, result.data.refreshToken, {
        ...CookieConfig.COOKIE_OPTIONS,
        maxAge: CookieConfig.REFRESH_TOKEN_MAX_AGE,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING, // ✅ Подписанный cookie
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
    
    // ✅ DUAL MODE: получаем refresh token из cookies ИЛИ body
    let refreshToken: string | undefined;
    
    if (useCookies) {
      // Получаем из signed cookies
      // В NestJS + Fastify cookies доступны напрямую через req
      const reqWithCookies = req as any;
      if (CookieConfig.ENABLE_COOKIE_SIGNING) {
        const signedCookie = reqWithCookies.cookies?.[CookieConfig.REFRESH_TOKEN_NAME];
        if (signedCookie && reqWithCookies.unsignCookie) {
          const unsigned = reqWithCookies.unsignCookie(signedCookie);
          refreshToken = unsigned?.valid ? unsigned.value : undefined;
          
          // Если подпись невалидна - возможная атака
          if (unsigned && !unsigned.valid) {
            throw new UnauthorizedException('Invalid refresh token signature. Possible tampering.');
          }
        }
      } else {
        refreshToken = reqWithCookies.cookies?.[CookieConfig.REFRESH_TOKEN_NAME];
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
      // Устанавливаем новые подписанные cookies
      const rawReply = res as any;
      rawReply.setCookie(CookieConfig.ACCESS_TOKEN_NAME, result.data.accessToken, {
        ...CookieConfig.COOKIE_OPTIONS,
        maxAge: CookieConfig.ACCESS_TOKEN_MAX_AGE,
        signed: CookieConfig.ENABLE_COOKIE_SIGNING,
      });
      
      rawReply.setCookie(CookieConfig.REFRESH_TOKEN_NAME, result.data.refreshToken, {
        ...CookieConfig.COOKIE_OPTIONS,
        maxAge: CookieConfig.REFRESH_TOKEN_MAX_AGE,
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
    
    await this.authService.logout(req.user, ip, userAgent);
    
    if (useCookies) {
      // Очищаем cookies
      const rawReply = res as any;
      rawReply.clearCookie(CookieConfig.ACCESS_TOKEN_NAME);
      rawReply.clearCookie(CookieConfig.REFRESH_TOKEN_NAME);
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
    // Читаем access token из httpOnly cookie
    const rawRequest = request as any;
    const accessToken = rawRequest.unsignCookie(
      rawRequest.cookies[CookieConfig.ACCESS_TOKEN_NAME]
    );

    if (!accessToken || !accessToken.valid) {
      throw new UnauthorizedException('No valid access token in cookies');
    }

    // Возвращаем токен для Socket.IO (он уже валидный и короткоживущий - 15 минут)
    return {
      success: true,
      data: {
        token: accessToken.value,
        expiresIn: 900, // 15 минут в секундах
      },
    };
  }

  @Post('admin/force-logout')
  @UseGuards(CookieJwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Force logout user (admin only)' })
  @ApiResponse({ status: 200, description: 'User forcefully logged out' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async forceLogout(
    @Request() req,
    @Body() body: { userId: number; role: string },
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    // Проверяем что запрос от админа
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can force logout users');
    }

    const userAgent = this.getUserAgent(headers);
    await this.authService.forceLogout(
      body.userId,
      body.role,
      req.user.sub,
      req.user.role,
      ip,
      userAgent,
    );

    return {
      success: true,
      message: `User #${body.userId} (${body.role}) has been forcefully logged out`,
    };
  }
}

