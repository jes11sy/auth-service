import { Controller, Get, Query, UseGuards, Request, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CookieJwtAuthGuard } from '../auth/guards/cookie-jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';

interface AuditLogQuery {
  userId?: string;
  role?: string;
  eventType?: string;
  startDate?: string;
  endDate?: string;
  page?: string;
  limit?: string;
}

@ApiTags('audit')
@Controller('auth/audit')
@UseGuards(CookieJwtAuthGuard)
export class AuditController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('user-logs')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get user activity logs (Admin only)' })
  @ApiResponse({ status: 200, description: 'User logs retrieved' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getUserLogs(@Query() query: AuditLogQuery, @Request() req) {
    // Только админ может просматривать логи
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view user logs');
    }

    const page = parseInt(query.page || '1', 10);
    const limit = parseInt(query.limit || '50', 10);
    const skip = (page - 1) * limit;

    // Строим WHERE условие
    const where: any = {};

    if (query.userId) {
      where.userId = parseInt(query.userId, 10);
    }

    if (query.role) {
      where.role = query.role;
    }

    if (query.eventType) {
      where.eventType = query.eventType;
    }

    if (query.startDate || query.endDate) {
      where.timestamp = {};
      if (query.startDate) {
        where.timestamp.gte = new Date(query.startDate);
      }
      if (query.endDate) {
        where.timestamp.lte = new Date(query.endDate);
      }
    }

    // Получаем общее количество
    const total = await this.prisma.auditLog.count({ where });

    // Получаем логи
    const logs = await this.prisma.auditLog.findMany({
      where,
      orderBy: {
        timestamp: 'desc',
      },
      skip,
      take: limit,
    });

    // Обогащаем данными пользователей (ФИО)
    const enrichedLogs = await Promise.all(
      logs.map(async (log) => {
        let fullName = 'Unknown User';
        
        if (log.userId && log.role) {
          fullName = await this.getUserFullName(log.userId, log.role);
        }

        return {
          id: log.id,
          timestamp: log.timestamp.toISOString(),
          eventType: log.eventType,
          userId: log.userId,
          role: log.role,
          login: log.login,
          fullName,
          ip: log.ip,
          userAgent: log.userAgent,
          success: log.success,
          metadata: log.metadata,
        };
      })
    );

    return {
      success: true,
      data: {
        logs: enrichedLogs,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      },
    };
  }

  /**
   * Получить ФИО пользователя по ID и роли
   */
  private async getUserFullName(userId: number, role: string): Promise<string> {
    try {
      let user: any = null;

      switch (role) {
        case 'admin':
          user = await this.prisma.callcentreAdmin.findUnique({ where: { id: userId } });
          break;
        case 'director':
          user = await this.prisma.director.findUnique({ where: { id: userId } });
          break;
        case 'callcentre_operator':
        case 'operator':
          user = await this.prisma.callcentreOperator.findUnique({ where: { id: userId } });
          break;
        case 'master':
          user = await this.prisma.master.findUnique({ where: { id: userId } });
          break;
      }

      return user?.name || `User #${userId}`;
    } catch (error) {
      return `User #${userId}`;
    }
  }
}

