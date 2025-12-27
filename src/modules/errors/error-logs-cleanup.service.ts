import { Injectable, Logger } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../prisma/prisma.service';

@Injectable()
export class ErrorLogsCleanupService {
  private readonly logger = new Logger(ErrorLogsCleanupService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * Очищаем error_logs старше 7 дней
   * Запускается каждый день в 4:00 ночи
   */
  @Cron('0 4 * * *')
  async handleCron() {
    this.logger.log('Starting error logs cleanup (7 days retention)...');
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);

    try {
      const { count } = await this.prisma.errorLog.deleteMany({
        where: {
          timestamp: {
            lt: sevenDaysAgo,
          },
        },
      });
      this.logger.log(`Cleaned up ${count} old error logs (>7 days).`);
    } catch (error) {
      this.logger.error('Failed to clean up old error logs:', error.message);
    }
  }
}

