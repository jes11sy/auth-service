import { Injectable, UnauthorizedException, Logger } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcryptjs';
import { PrismaService } from '../prisma/prisma.service';
import { LoginDto } from './dto/login.dto';

export enum UserRole {
  CALLCENTRE_ADMIN = 'CALLCENTRE_ADMIN',
  CALLCENTRE_OPERATOR = 'CALLCENTRE_OPERATOR',
  DIRECTOR = 'DIRECTOR',
  MASTER = 'MASTER',
}

@Injectable()
export class AuthService {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    private prisma: PrismaService,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  async validateUser(login: string, password: string, role: UserRole): Promise<any> {
    let user: any = null;

    try {
      switch (role) {
        case UserRole.CALLCENTRE_ADMIN:
          user = await this.prisma.callcentreAdmin.findUnique({
            where: { login },
          });
          break;

        case UserRole.CALLCENTRE_OPERATOR:
          user = await this.prisma.callcentreOperator.findUnique({
            where: { login },
          });
          
          // Проверка статуса оператора
          if (user && user.status !== 'active') {
            throw new UnauthorizedException('Account is not active');
          }
          break;

        case UserRole.DIRECTOR:
          user = await this.prisma.director.findUnique({
            where: { login },
          });
          break;

        case UserRole.MASTER:
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
      this.logger.error(`Validation error for ${login}:`, error.message);
      throw error;
    }
  }

  async login(loginDto: LoginDto) {
    const { login, password, role } = loginDto;

    this.logger.log(`Login attempt: ${login} as ${role}`);

    const user = await this.validateUser(login, password, role);

    if (!user) {
      throw new UnauthorizedException('Invalid credentials');
    }

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

    this.logger.log(`Login successful: ${login} (${role})`);

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

      const newPayload = {
        sub: payload.sub,
        login: payload.login,
        role: payload.role,
        name: payload.name,
        cities: payload.cities,
      };

      const newAccessToken = this.jwtService.sign(newPayload);

      return {
        success: true,
        data: {
          accessToken: newAccessToken,
        },
      };
    } catch (error) {
      throw new UnauthorizedException('Invalid refresh token');
    }
  }

  async getProfile(user: any) {
    const { sub: id, role } = user;

    let profile: any = null;

    switch (role) {
      case UserRole.CALLCENTRE_ADMIN:
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

      case UserRole.CALLCENTRE_OPERATOR:
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

      case UserRole.DIRECTOR:
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

      case UserRole.MASTER:
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
}

