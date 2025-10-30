import { Controller, Post, Body, Get, UseGuards, Request, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
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

  @Get('health')
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
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Login user by role' })
  @ApiResponse({ status: 200, description: 'Login successful' })
  @ApiResponse({ status: 401, description: 'Invalid credentials' })
  async login(@Body() loginDto: LoginDto) {
    return this.authService.login(loginDto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Refresh access token' })
  @ApiResponse({ status: 200, description: 'Token refreshed' })
  @ApiResponse({ status: 401, description: 'Invalid refresh token' })
  async refresh(@Body() refreshTokenDto: RefreshTokenDto) {
    return this.authService.refreshToken(refreshTokenDto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Logout user (revokes all refresh tokens)' })
  @ApiResponse({ status: 200, description: 'Logout successful' })
  async logout(@Request() req) {
    await this.authService.logout(req.user);
    return {
      success: true,
      message: 'Logout successful',
    };
  }

  @Get('validate')
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
  @UseGuards(JwtAuthGuard)
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user profile' })
  @ApiResponse({ status: 200, description: 'Profile retrieved' })
  async getProfile(@Request() req) {
    return this.authService.getProfile(req.user);
  }
}

