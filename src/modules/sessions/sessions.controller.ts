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
  createdAt: string;
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
   */
  @Get()
  @Throttle({ default: { limit: 30, ttl: 60000 } })
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Get all active sessions (admin only)' })
  @ApiResponse({ status: 200, description: 'Active sessions retrieved' })
  @ApiResponse({ status: 403, description: 'Forbidden - Admin role required' })
  async getActiveSessions(@Request() req): Promise<any> {
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view active sessions');
    }

    const sessions: ActiveSession[] = [];
    const keys = await this.getAllUserTokenKeys();

    for (const key of keys) {
      const match = key.match(/user_tokens:(.*?):(\d+)/);
      if (!match) continue;

      const role = match[1];
      const userId = parseInt(match[2], 10);

      const fullName = await this.getUserFullName(userId, role);
      if (!fullName) continue;

      const lastLogin = await this.prisma.auditAuth.findFirst({
        where: {
          userId,
          role,
          eventType: 'auth.login.success',
        },
        orderBy: { createdAt: 'desc' },
      });

      if (!lastLogin) continue;

      const lastActivity = await this.prisma.auditAuth.findFirst({
        where: {
          userId,
          role,
          eventType: {
            in: ['auth.profile.access', 'auth.token.refresh'],
          },
        },
        orderBy: { createdAt: 'desc' },
      });

      const parsedUA = parseUserAgent(lastLogin.userAgent);

      sessions.push({
        userId,
        fullName,
        role,
        device: parsedUA.device,
        deviceType: parsedUA.deviceType,
        ip: lastLogin.ip,
        loginDate: lastLogin.createdAt.toISOString(),
        lastActivity: (lastActivity?.createdAt || lastLogin.createdAt).toISOString(),
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
    if (req.user.role !== 'admin') {
      throw new ForbiddenException('Only administrators can view user session details');
    }

    const userId = parseInt(userIdParam, 10);

    let userInfo: { fullName: string; role: string } | null = null;

    const admin = await this.prisma.admin.findUnique({ where: { id: userId } });
    if (admin) userInfo = { fullName: admin.login, role: 'admin' };

    if (!userInfo) {
      const operator = await this.prisma.operator.findUnique({ where: { id: userId } });
      if (operator) userInfo = { fullName: operator.name, role: 'operator' };
    }

    if (!userInfo) {
      const director = await this.prisma.director.findUnique({ where: { id: userId } });
      if (director) userInfo = { fullName: director.name, role: 'director' };
    }

    if (!userInfo) {
      const master = await this.prisma.master.findUnique({ where: { id: userId } });
      if (master) userInfo = { fullName: master.name, role: 'master' };
    }

    if (!userInfo) {
      throw new NotFoundException(`User with ID ${userId} not found`);
    }

    const lastLogin = await this.prisma.auditAuth.findFirst({
      where: { userId, eventType: 'auth.login.success' },
      orderBy: { createdAt: 'desc' },
    });

    const lastActivity = await this.prisma.auditAuth.findFirst({
      where: {
        userId,
        eventType: { in: ['auth.profile.access', 'auth.token.refresh'] },
      },
      orderBy: { createdAt: 'desc' },
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
        loginDate: lastLogin.createdAt.toISOString(),
        lastActivity: (lastActivity?.createdAt || lastLogin.createdAt).toISOString(),
      };
    }

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const loginHistory = await this.prisma.auditAuth.findMany({
      where: {
        userId,
        eventType: { in: ['auth.login.success', 'auth.login.failed'] },
        createdAt: { gte: thirtyDaysAgo },
      },
      orderBy: { createdAt: 'desc' },
      take: 100,
    });

    const history: LoginHistoryEntry[] = loginHistory.map((log) => {
      const parsedUA = parseUserAgent(log.userAgent);
      return {
        id: log.id,
        createdAt: log.createdAt.toISOString(),
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

  private async getAllUserTokenKeys(): Promise<string[]> {
    const keys: string[] = [];
    let cursor = '0';

    do {
      const result = await (this.redis as any).client.scan(
        cursor, 'MATCH', 'user_tokens:*', 'COUNT', 100,
      );
      cursor = result[0];
      keys.push(...result[1]);
    } while (cursor !== '0');

    return keys;
  }

  private async getUserFullName(userId: number, role: string): Promise<string | null> {
    try {
      if (role === 'admin') {
        const user = await this.prisma.admin.findUnique({ where: { id: userId } });
        return user?.login || null;
      } else if (role === 'operator') {
        const user = await this.prisma.operator.findUnique({ where: { id: userId } });
        return user?.name || null;
      } else if (role === 'director') {
        const user = await this.prisma.director.findUnique({ where: { id: userId } });
        return user?.name || null;
      } else if (role === 'master') {
        const user = await this.prisma.master.findUnique({ where: { id: userId } });
        return user?.name || null;
      }
    } catch {
      return null;
    }
    return null;
  }
}
