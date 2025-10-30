import { Injectable, UnauthorizedException, Logger, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { LoginDto } from './dto/login.dto';

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
    private redis: RedisService,
  ) {}

  async validateUser(login: string, password: string, role: string): Promise<any> {
    let user: any = null;

    try {
      switch (role) {
        case 'admin':
          user = await this.prisma.callcentreAdmin.findUnique({
            where: { login },
          });
          break;

        case 'operator':
          user = await this.prisma.callcentreOperator.findUnique({
            where: { login },
          });
          
          // Проверка статуса оператора
          if (user && user.status !== 'active') {
            throw new UnauthorizedException('Account is not active');
          }
          break;

        case 'director':
          user = await this.prisma.director.findUnique({
            where: { login },
          });
          break;

        case 'master':
          user = await this.prisma.master.findUnique({
            where: { login },
          });
          
          // Проверка статуса мастера и наличия пароля
          if (user && !user.password) {
            throw new UnauthorizedException('Password not set for this master');
          }
          if (user && user.statusWork !== 'работает') {
            throw new UnauthorizedException('Master account is inactive');
          }
          break;

        default:
          throw new UnauthorizedException('Invalid role');
      }

      if (!user) {
        return null;
      }

      // Проверка пароля
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return null;
      }

      // Удаляем пароль из результата
      const { password: _, ...result } = user;
      return { ...result, role };
    } catch (error) {
      this.logger.error(`Validation error:`, error.message);
      throw error;
    }
  }

  async login(loginDto: LoginDto) {
    const { login, password, role } = loginDto;

    // Проверка brute-force блокировки
    const lockIdentifier = `${login}:${role}`;
    const isLocked = await this.redis.isAccountLocked(lockIdentifier, 10);

    if (isLocked) {
      const ttl = await this.redis.getLockTTL(lockIdentifier);
      const minutesLeft = Math.ceil(ttl / 60);
      this.logger.warn(`Account locked: ${role} user (attempts exceeded)`);
      throw new ForbiddenException(
        `Too many login attempts. Try again in ${minutesLeft} minute(s).`,
      );
    }

    const user = await this.validateUser(login, password, role);

    if (!user) {
      // Записываем неудачную попытку
      const attempts = await this.redis.recordLoginAttempt(lockIdentifier);
      const remainingAttempts = 10 - attempts;
      
      this.logger.warn(`Failed login attempt for ${role} user (${attempts}/10 attempts)`);
      
      if (remainingAttempts > 0) {
        throw new UnauthorizedException(
          `Invalid credentials. ${remainingAttempts} attempt(s) remaining.`,
        );
      } else {
        throw new ForbiddenException(
          'Too many failed login attempts. Account locked for 10 minutes.',
        );
      }
    }

    // Успешный вход - сбрасываем счетчик попыток
    await this.redis.resetLoginAttempts(lockIdentifier);

    const payload = {
      sub: user.id,
      login: user.login,
      role: user.role,
      name: user.name,
      cities: user.cities || undefined,
    };

    const accessToken = this.jwtService.sign(payload);
    const refreshToken = this.jwtService.sign(payload, {
      secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d'),
    });

    // Сохраняем refresh токен в Redis
    const refreshExpirationStr = this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d');
    const refreshTTL = this.parseExpirationToSeconds(refreshExpirationStr);
    await this.redis.saveRefreshToken(user.id, user.role, refreshToken, refreshTTL);

    this.logger.log(`Login successful for ${role} user`);

    return {
      success: true,
      message: 'Login successful',
      data: {
        user: {
          id: user.id,
          login: user.login,
          name: user.name,
          role: user.role,
          cities: user.cities,
          city: user.city, // для оператора
        },
        accessToken,
        refreshToken,
      },
    };
  }

  async refreshToken(refreshToken: string) {
    try {
      const payload = this.jwtService.verify(refreshToken, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
      });

      // Проверяем, существует ли токен в Redis
      const isValid = await this.redis.isRefreshTokenValid(
        payload.sub,
        payload.role,
        refreshToken,
      );

      if (!isValid) {
        throw new UnauthorizedException('Refresh token has been revoked');
      }

      // Удаляем старый refresh токен (одноразовое использование)
      await this.redis.revokeRefreshToken(payload.sub, payload.role, refreshToken);

      const newPayload = {
        sub: payload.sub,
        login: payload.login,
        role: payload.role,
        name: payload.name,
        cities: payload.cities,
      };

      // Генерируем новую пару токенов
      const newAccessToken = this.jwtService.sign(newPayload);
      const newRefreshToken = this.jwtService.sign(newPayload, {
        secret: this.configService.get<string>('JWT_REFRESH_SECRET'),
        expiresIn: this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d'),
      });

      // Сохраняем новый refresh токен в Redis
      const refreshExpirationStr = this.configService.get<string>('JWT_REFRESH_EXPIRATION', '7d');
      const refreshTTL = this.parseExpirationToSeconds(refreshExpirationStr);
      await this.redis.saveRefreshToken(payload.sub, payload.role, newRefreshToken, refreshTTL);

      this.logger.log(`Token refreshed for ${payload.role} user`);

      return {
        success: true,
        data: {
          accessToken: newAccessToken,
          refreshToken: newRefreshToken,
        },
      };
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }
      this.logger.error('Token refresh error:', error.message);
      throw new UnauthorizedException('Invalid or expired refresh token');
    }
  }

  async getProfile(user: any) {
    const { sub: id, role } = user;

    let profile: any = null;

    switch (role) {
      case 'admin':
        profile = await this.prisma.callcentreAdmin.findUnique({
          where: { id },
          select: {
            id: true,
            login: true,
            note: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case 'operator':
        profile = await this.prisma.callcentreOperator.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            city: true,
            status: true,
            statusWork: true,
            dateCreate: true,
            note: true,
            sipAddress: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case 'director':
        profile = await this.prisma.director.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            cities: true,
            dateCreate: true,
            note: true,
            tgId: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;

      case 'master':
        profile = await this.prisma.master.findUnique({
          where: { id },
          select: {
            id: true,
            name: true,
            login: true,
            cities: true,
            statusWork: true,
            dateCreate: true,
            note: true,
            tgId: true,
            chatId: true,
            createdAt: true,
            updatedAt: true,
          },
        });
        break;
    }

    if (!profile) {
      throw new UnauthorizedException('User profile not found');
    }

    return {
      success: true,
      data: {
        ...profile,
        role,
      },
    };
  }

  /**
   * Logout пользователя - отзыв всех refresh токенов
   */
  async logout(user: any) {
    const { sub: userId, role } = user;
    await this.redis.revokeAllUserTokens(userId, role);
    this.logger.log(`User logged out: ${role} user`);
  }

  /**
   * Парсинг строки времени в секунды (например, '7d' -> 604800)
   */
  private parseExpirationToSeconds(expiration: string): number {
    const match = expiration.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 7 * 24 * 60 * 60; // по умолчанию 7 дней
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      default:
        return 7 * 24 * 60 * 60;
    }
  }
}
