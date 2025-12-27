import { Module } from '@nestjs/common';
import { AuditService } from './audit.service';
import { AuditCleanupService } from './audit-cleanup.service';
import { AuditController } from './audit.controller';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  controllers: [AuditController],
  providers: [AuditService, AuditCleanupService],
  exports: [AuditService],
})
export class AuditModule {}

