import { Module } from '@nestjs/common';
import { ErrorLogsController } from './error-logs.controller';
import { ErrorLogsCleanupService } from './error-logs-cleanup.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [ErrorLogsController],
  providers: [ErrorLogsCleanupService],
})
export class ErrorLogsModule {}

