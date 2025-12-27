import { Controller, Get, Query, UseGuards, Request, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CookieJwtAuthGuard } from '../auth/guards/cookie-jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';

interface ErrorLogsQuery {
  service?: string;
  errorType?: string;
  startDate?: string;
  endDate?: string;
  page?: string;
  limit?: string;
}

@ApiTags('errors')
@Controller('auth/admin/errors')
@UseGuards(CookieJwtAuthGuard)
export class ErrorLogsController {
  constructor(private readonly prisma: PrismaService) {}

  @Get('/')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get error logs (Admin only)' })
  @ApiResponse({ status: 200, description: 'Error logs retrieved' })
  @ApiResponse({ status: 403, description: 'Forbidden' })
  async getErrorLogs(@Query() query: ErrorLogsQuery, @Request() req) {
    // Только админ может просматривать логи ошибок
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view error logs');
    }

    const page = parseInt(query.page || '1', 10);
    const limit = parseInt(query.limit || '50', 10);
    const skip = (page - 1) * limit;

    // Строим WHERE условие
    const where: any = {};

    if (query.service) {
      where.service = query.service;
    }

    if (query.errorType) {
      where.errorType = {
        contains: query.errorType,
        mode: 'insensitive',
      };
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
    const total = await this.prisma.errorLog.count({ where });

    // Получаем логи
    const logs = await this.prisma.errorLog.findMany({
      where,
      orderBy: {
        timestamp: 'desc',
      },
      skip,
      take: limit,
    });

    return {
      success: true,
      data: {
        logs: logs.map(log => ({
          id: log.id,
          timestamp: log.timestamp.toISOString(),
          service: log.service,
          errorType: log.errorType,
          errorMessage: log.errorMessage,
          stackTrace: log.stackTrace,
          userId: log.userId,
          userRole: log.userRole,
          requestUrl: log.requestUrl,
          requestMethod: log.requestMethod,
          ip: log.ip,
          userAgent: log.userAgent,
          metadata: log.metadata,
        })),
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit),
        },
      },
    };
  }

  @Get('/services')
  @ApiBearerAuth()
  @ApiOperation({ summary: 'Get list of services with errors (Admin only)' })
  @ApiResponse({ status: 200, description: 'Services list retrieved' })
  async getServices(@Request() req) {
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view services');
    }

    const services = await this.prisma.errorLog.groupBy({
      by: ['service'],
      _count: {
        id: true,
      },
      orderBy: {
        _count: {
          id: 'desc',
        },
      },
    });

    return {
      success: true,
      data: services.map(s => ({
        service: s.service,
        count: s._count.id,
      })),
    };
  }
}

