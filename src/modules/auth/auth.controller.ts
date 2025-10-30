import { Controller, Post, Body, Get, UseGuards, Request, HttpCode, HttpStatus, Ip, Headers } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle, SkipThrottle } from '@nestjs/throttler';
import { AuthService } from './auth.service';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { RedisService } from '../redis/redis.service';
import { PrismaService } from '../prisma/prisma.service';

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
  @ApiOperation({ summary: 'Login user by role' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async login(
    @Body() loginDto: LoginDto,
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    const userAgent = this.getUserAgent(headers);
    return this.authService.login(loginDto, ip, userAgent);
  }

  @Post('refresh')
  @Throttle({ default: { limit: 20, ttl: 60000 } }) // ✅ VULN-001: 20 обновлений в минуту
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Token refreshed' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  @ApiResponse({ status: 429, description: 'Too many requests' })
  async refresh(
    @Body() refreshTokenDto: RefreshTokenDto,
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    const userAgent = this.getUserAgent(headers);
    return this.authService.refreshToken(refreshTokenDto.refreshToken, ip, userAgent);
  }

  @Post('logout')
  @Throttle({ default: { limit: 10, ttl: 60000 } }) // ✅ 10 logout запросов в минуту
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout user (revokes all refresh tokens)' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  async logout(
    @Request() req,
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    const userAgent = this.getUserAgent(headers);
    await this.authService.logout(req.user, ip, userAgent);
    return {
      success: true,
      message: 'Logout successful',
    };
  }

  @Get('validate')
  @Throttle({ default: { limit: 50, ttl: 60000 } }) // ✅ 50 валидаций в минуту
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Validate JWT token' })
  @ApiResponse({ status: 200, description: 'Token is valid' })
  @ApiResponse({ status: 401, description: 'Invalid token' })
  async validate(@Request() req) {
    return {
      valid: true,
      user: req.user,
    };
  }

  @Get('profile')
  @Throttle({ default: { limit: 30, ttl: 60000 } }) // ✅ 30 запросов профиля в минуту
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved' })
  async getProfile(
    @Request() req,
    @Ip() ip: string,
    @Headers() headers: any,
  ) {
    const userAgent = this.getUserAgent(headers);
    return this.authService.getProfile(req.user, ip, userAgent);
  }
}

