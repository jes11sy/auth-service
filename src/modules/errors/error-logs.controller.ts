import { Controller, Get, Query, UseGuards, Request, ForbiddenException } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { CookieJwtAuthGuard } from '../auth/guards/cookie-jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';

interface ErrorLogsQuery {
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
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view error logs');
    }

    const page = parseInt(query.page || '1', 10);
    const limit = parseInt(query.limit || '50', 10);
    const skip = (page - 1) * limit;

    const where: any = {};

    if (query.errorType) {
      where.errorType = {
        contains: query.errorType,
        mode: 'insensitive',
      };
    }

    if (query.startDate || query.endDate) {
      where.createdAt = {};
      if (query.startDate) {
        where.createdAt.gte = new Date(query.startDate);
      }
      if (query.endDate) {
        where.createdAt.lte = new Date(query.endDate);
      }
    }

    const total = await this.prisma.errorAuth.count({ where });

    const logs = await this.prisma.errorAuth.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      skip,
      take: limit,
    });

    return {
      success: true,
      data: {
        logs: logs.map(log => ({
          id: log.id,
          createdAt: log.createdAt.toISOString(),
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
}
