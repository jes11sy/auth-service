import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { ThrottlerModule } from '@nestjs/throttler';
import { ScheduleModule } from '@nestjs/schedule';
import { PrometheusModule } from '@willsoto/nestjs-prometheus';
import { AuthModule } from './modules/auth/auth.module';
import { PrismaModule } from './modules/prisma/prisma.module';
import { RedisModule } from './modules/redis/redis.module';
import { SessionsModule } from './modules/sessions/sessions.module';
import { AuditModule } from './modules/audit/audit.module';
import { ErrorLogsModule } from './modules/errors/error-logs.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.env',
    }),
    // ✅ Schedule Module для Cron jobs
    ScheduleModule.forRoot(),
    // ✅ ИСПРАВЛЕНИЕ VULN-001: Endpoint-specific rate limiting
    ThrottlerModule.forRoot([
      {
        name: 'default',
        ttl: 60000, // 60 seconds
        limit: 100, // 100 requests per minute (global fallback)
      },
    ]),
    // Prometheus метрики для мониторинга
    PrometheusModule.register({
      defaultMetrics: {
        enabled: true,
      },
      path: '/metrics',
    }),
    PrismaModule,
    RedisModule,
    AuthModule,
    SessionsModule,
    AuditModule,
    ErrorLogsModule,
  ],
})
export class AppModule {}

