import { Module } from '@nestjs/common';
import { JwtModule } from '@nestjs/jwt';
import { PassportModule } from '@nestjs/passport';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { APP_INTERCEPTOR } from '@nestjs/core';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { JwtStrategy } from './strategies/jwt.strategy';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { ProactiveRefreshInterceptor } from './interceptors/proactive-refresh.interceptor';
import { AuditModule } from '../audit/audit.module';
import { PrismaModule } from '../prisma/prisma.module';
import { RedisModule } from '../redis/redis.module';

@Module({
  imports: [
    PassportModule.register({ defaultStrategy: 'jwt' }),
    JwtModule.registerAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: async (configService: ConfigService) => ({
        secret: configService.get<string>('JWT_SECRET'),
        signOptions: {
          // ✅ FIX #36: Используем JWT_EXPIRATION из .env вместо hardcoded '15m'
          expiresIn: configService.get<string>('JWT_EXPIRATION') || '15m',
        },
      }),
    }),
    AuditModule,
    PrismaModule,
    RedisModule,
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    JwtStrategy,
    JwtAuthGuard,
    ProactiveRefreshInterceptor,
    {
      provide: APP_INTERCEPTOR,
      useClass: ProactiveRefreshInterceptor,
    },
  ],
  exports: [AuthService, JwtAuthGuard],
})
export class AuthModule {}

