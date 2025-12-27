import { Controller, Get, Param, UseGuards, Request, ForbiddenException, NotFoundException, HttpCode, HttpStatus } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse, ApiBearerAuth } from '@nestjs/swagger';
import { Throttle } from '@nestjs/throttler';
import { CookieJwtAuthGuard } from '../auth/guards/cookie-jwt-auth.guard';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';
import { parseUserAgent } from '../auth/helpers/user-agent.helper';

interface ActiveSession {
  userId: number;
  fullName: string;
  role: string;
  device: string;
  deviceType: 'mobile' | 'tablet' | 'desktop';
  ip: string;
  loginDate: string;
  lastActivity: string;
}

interface LoginHistoryEntry {
  id: number;
  timestamp: string;
  ip: string;
  device: string;
  deviceType: 'mobile' | 'tablet' | 'desktop';
  status: 'success' | 'failed';
  reason?: string;
}

@ApiTags('admin/sessions')
@Controller('auth/admin/sessions')
@UseGuards(CookieJwtAuthGuard)
@ApiBearerAuth()
export class SessionsController {
  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  /**
   * GET /auth/admin/sessions
   * Получить список всех активных сессий
   */
  @Get()
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get all active sessions (admin only)' })
  @ApiResponse({ status: 200, description: 'Active sessions retrieved' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async getActiveSessions(@Request() req): Promise<any> {
    // Проверка роли админа
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view active sessions');
    }

    const sessions: ActiveSession[] = [];

    // Получаем все активные токены из Redis
    const keys = await this.getAllUserTokenKeys();

    for (const key of keys) {
      const match = key.match(/user_tokens:(.*?):(\d+)/);
      if (!match) continue;

      const role = match[1];
      const userId = parseInt(match[2], 10);

      // Получаем ФИО пользователя из соответствующей таблицы
      const fullName = await this.getUserFullName(userId, role);
      if (!fullName) continue;

      // Получаем последний успешный логин из audit_logs
      const lastLogin = await this.prisma.auditLog.findFirst({
        where: {
          userId,
          role,
          eventType: 'auth.login.success',
        },
        orderBy: {
          timestamp: 'desc',
        },
      });

      if (!lastLogin) continue;

      // Получаем последнюю активность (PROFILE_ACCESS или TOKEN_REFRESH)
      const lastActivity = await this.prisma.auditLog.findFirst({
        where: {
          userId,
          role,
          eventType: {
            in: ['auth.profile.access', 'auth.token.refresh'],
          },
        },
        orderBy: {
          timestamp: 'desc',
        },
      });

      const parsedUA = parseUserAgent(lastLogin.userAgent);

      sessions.push({
        userId,
        fullName,
        role,
        device: parsedUA.device,
        deviceType: parsedUA.deviceType,
        ip: lastLogin.ip,
        loginDate: lastLogin.timestamp.toISOString(),
        lastActivity: (lastActivity?.timestamp || lastLogin.timestamp).toISOString(),
      });
    }

    return {
      success: true,
      data: {
        sessions,
        total: sessions.length,
      },
    };
  }

  /**
   * GET /auth/admin/sessions/:userId
   * Получить детальную информацию о сессиях пользователя
   */
  @Get(':userId')
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get user session details (admin only)' })
  @ApiResponse({ status: 200, description: 'User session details retrieved' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  @ApiResponse({ status: 404, description: 'User not found' })
  async getUserSessionDetails(
    @Request() req,
    @Param('userId') userIdParam: string,
  ): Promise<any> {
    // Проверка роли админа
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view user session details');
    }

    const userId = parseInt(userIdParam, 10);

    // Получаем информацию о пользователе из всех таблиц
    let userInfo: { fullName: string; role: string } | null = null;

    // Проверяем admin
    const admin = await this.prisma.callcentreAdmin.findUnique({ where: { id: userId } });
    if (admin) {
      userInfo = { fullName: admin.login, role: 'admin' };
    }

    // Проверяем callcenter
    if (!userInfo) {
      const operator = await this.prisma.callcentreOperator.findUnique({ where: { id: userId } });
      if (operator) {
        userInfo = { fullName: operator.name, role: 'callcenter' };
      }
    }

    // Проверяем director
    if (!userInfo) {
      const director = await this.prisma.director.findUnique({ where: { id: userId } });
      if (director) {
        userInfo = { fullName: director.name, role: 'director' };
      }
    }

    // Проверяем master
    if (!userInfo) {
      const master = await this.prisma.master.findUnique({ where: { id: userId } });
      if (master) {
        userInfo = { fullName: master.name, role: 'master' };
      }
    }

    if (!userInfo) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    // Получаем текущую сессию
    const lastLogin = await this.prisma.auditLog.findFirst({
      where: {
        userId,
        eventType: 'auth.login.success',
      },
      orderBy: {
        timestamp: 'desc',
      },
    });

    const lastActivity = await this.prisma.auditLog.findFirst({
      where: {
        userId,
        eventType: {
          in: ['auth.profile.access', 'auth.token.refresh'],
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
    });

    let currentSession: {
      device: string;
      deviceType: 'mobile' | 'tablet' | 'desktop';
      ip: string;
      loginDate: string;
      lastActivity: string;
    } | null = null;
    
    if (lastLogin) {
      const parsedUA = parseUserAgent(lastLogin.userAgent);
      currentSession = {
        device: parsedUA.device,
        deviceType: parsedUA.deviceType,
        ip: lastLogin.ip,
        loginDate: lastLogin.timestamp.toISOString(),
        lastActivity: (lastActivity?.timestamp || lastLogin.timestamp).toISOString(),
      };
    }

    // Получаем историю авторизаций за последние 30 дней
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const loginHistory = await this.prisma.auditLog.findMany({
      where: {
        userId,
        eventType: {
          in: ['auth.login.success', 'auth.login.failed'],
        },
        timestamp: {
          gte: thirtyDaysAgo,
        },
      },
      orderBy: {
        timestamp: 'desc',
      },
      take: 100, // Лимит на 100 записей
    });

    const history: LoginHistoryEntry[] = loginHistory.map((log) => {
      const parsedUA = parseUserAgent(log.userAgent);
      return {
        id: log.id,
        timestamp: log.timestamp.toISOString(),
        ip: log.ip,
        device: parsedUA.device,
        deviceType: parsedUA.deviceType,
        status: log.eventType === 'auth.login.success' ? 'success' : 'failed',
        reason: log.eventType === 'auth.login.failed' ? (log.metadata as any)?.reason : undefined,
      };
    });

    return {
      success: true,
      data: {
        userId,
        fullName: userInfo.fullName,
        role: userInfo.role,
        currentSession,
        loginHistory: history,
      },
    };
  }

  /**
   * Вспомогательный метод: получить все ключи user_tokens из Redis
   */
  private async getAllUserTokenKeys(): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';

    do {
      const result = await (this.redis as any).client.scan(
        cursor,
        'MATCH',
        'user_tokens:*',
        'COUNT',
        100,
      );

      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');

    return keys;
  }

  /**
   * Вспомогательный метод: получить ФИО пользователя по ID и роли
   */
  private async getUserFullName(userId: number, role: string): Promise<string | null> {
    try {
      if (role === 'admin') {
        const user = await this.prisma.callcentreAdmin.findUnique({ where: { id: userId } });
        return user?.login || null;
      } else if (role === 'operator' || role === 'callcenter') {
        const user = await this.prisma.callcentreOperator.findUnique({ where: { id: userId } });
        return user?.name || null;
      } else if (role === 'director') {
        const user = await this.prisma.director.findUnique({ where: { id: userId } });
        return user?.name || null;
      } else if (role === 'master') {
        const user = await this.prisma.master.findUnique({ where: { id: userId } });
        return user?.name || null;
      }
    } catch (error) {
      return null;
    }

    return null;
  }
}

