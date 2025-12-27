import { Module } from '@nestjs/common';
import { AuditService } from './audit.service';
import { AuditCleanupService } from './audit-cleanup.service';
import { PrismaModule } from '../prisma/prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [AuditService, AuditCleanupService],
  exports: [AuditService],
})
export class AuditModule {}

