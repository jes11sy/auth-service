import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class AuditCleanupService {
  private readonly logger = new Logger(AuditCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * ✅ Автоматическая очистка audit логов старше 30 дней
   * Запускается каждый день в 3:00 ночи
   */
  @Cron('0 3 * * *', {
    name: 'cleanup-old-audit-logs',
    timeZone: 'Europe/Moscow',
  })
  async cleanupOldAuditLogs() {
    try {
      const thirtyDaysAgo = new Date();
      thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

      this.logger.log(`[Cron] Starting audit logs cleanup (older than ${thirtyDaysAgo.toISOString()})`);

      const result = await this.prisma.auditLog.deleteMany({
        where: {
          timestamp: {
            lt: thirtyDaysAgo,
          },
        },
      });

      this.logger.log(`[Cron] ✅ Audit logs cleanup completed: ${result.count} records deleted`);
    } catch (error) {
      this.logger.error(`[Cron] ❌ Audit logs cleanup failed: ${error.message}`, error.stack);
    }
  }
}

