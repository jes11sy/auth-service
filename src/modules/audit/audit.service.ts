import { Injectable, Logger } from '@nestjs/common';
import { UserRole } from '../auth/interfaces/auth.interface';
import { PrismaService } from '../prisma/prisma.service';
import { RedisService } from '../redis/redis.service';

/**
 * Типы событий аудита безопасности
 */
export enum AuditEventType {
  LOGIN_SUCCESS = 'auth.login.success',
  LOGIN_FAILED = 'auth.login.failed',
  LOGIN_BLOCKED = 'auth.login.blocked',
  TOKEN_REFRESH = 'auth.token.refresh',
  TOKEN_REUSE_DETECTED = 'auth.token.reuse',
  LOGOUT = 'auth.logout',
  FORCE_LOGOUT = 'auth.force_logout',  // ✅ Принудительная деавторизация администратором
  PROFILE_ACCESS = 'auth.profile.access',
  TOKEN_VALIDATION = 'auth.token.validation',
}

/**
 * Структура записи аудита
 */
export interface AuditLogEntry {
  timestamp: string;
  eventType: AuditEventType;
  userId?: number;
  role?: UserRole;
  login?: string;
  ip: string;
  userAgent: string;
  success: boolean;
  metadata?: Record<string, any>;
}

/**
 * Сервис для структурированного логирования событий безопасности
 * 
 * Логи выводятся в JSON формате для удобной интеграции с:
 * - ELK Stack (Elasticsearch, Logstash, Kibana)
 * - Grafana Loki
 * - Splunk
 * - AWS CloudWatch
 * - Azure Monitor
 * 
 * Все события безопасности логируются для:
 * - Расследования инцидентов безопасности
 * - Compliance (GDPR, SOC 2, ISO 27001)
 * - Мониторинга и алертинга
 * - Forensics анализа
 */
@Injectable()
export class AuditService {
  private readonly logger = new Logger(AuditService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly redis: RedisService,
  ) {}

  /**
   * Базовый метод логирования событий аудита
   * ✅ Теперь пишет в БД + консоль
   * ✅ Throttling для profile.access и token.refresh (макс раз в 5 минут)
   * ✅ FIX #9: Оптимизирован через SETNX (1 round-trip вместо 2)
   */
  async log(entry: AuditLogEntry): Promise<void> {
    const timestamp = entry.timestamp || new Date().toISOString();
    
    // 🔥 Throttling для мусорных событий
    const throttleEvents = [
      AuditEventType.PROFILE_ACCESS,
      AuditEventType.TOKEN_REFRESH,
    ];
    
    if (throttleEvents.includes(entry.eventType as AuditEventType) && entry.userId) {
      const throttleKey = `audit:throttle:${entry.userId}:${entry.eventType}`;
      
      // ✅ FIX #9: Используем setNX для атомарной проверки и установки (1 round-trip)
      const wasSet = await this.redis.setNX(throttleKey, '1', 300);
      
      if (!wasSet) {
        // Ключ уже существовал - пропускаем логирование
        return;
      }
      // Ключ установлен - продолжаем логирование
    }
    
    // 1. JSON формат для парсинга в SIEM системах (консоль)
    this.logger.log(JSON.stringify({
      ...entry,
      timestamp,
    }));

    // 2. ✅ FIX #9: Fire-and-forget запись в БД - не блокируем основной запрос
    // Критические события (LOGIN_BLOCKED, TOKEN_REUSE) логируются с await в вызывающем коде
    this.prisma.auditAuth.create({
      data: {
        createdAt: new Date(timestamp),
        eventType: entry.eventType,
        userId: entry.userId,
        role: entry.role,
        login: entry.login,
        ip: entry.ip,
        userAgent: entry.userAgent,
        success: entry.success,
        metadata: entry.metadata || {},
      },
    }).catch(error => {
      // Если БД недоступна - логируем ошибку, но не падаем
      this.logger.error(`Failed to save audit log to DB: ${error.message}`);
    });

    // TODO: Опционально - отправка в внешние системы:
    // - await this.elasticsearchService.index({ index: 'audit-logs', body: entry });
    // - await this.lokiService.push(entry);
    // - await this.s3Service.archiveLog(entry);
  }

  /**
   * Успешный вход в систему
   */
  async logLoginSuccess(
    userId: number,
    role: UserRole,
    login: string,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.LOGIN_SUCCESS,
      userId,
      role,
      login,
      ip,
      userAgent,
      success: true,
    });
  }

  /**
   * Неудачная попытка входа
   */
  async logLoginFailed(
    login: string,
    role: UserRole,
    ip: string,
    userAgent: string,
    reason: string,
    attemptsCount?: number,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.LOGIN_FAILED,
      role,
      login,
      ip,
      userAgent,
      success: false,
      metadata: { 
        reason,
        attemptsCount,
      },
    });
  }

  /**
   * Блокировка учетной записи из-за превышения попыток входа
   */
  async logLoginBlocked(
    login: string,
    role: UserRole,
    ip: string,
    userAgent: string,
    lockDurationMinutes: number,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.LOGIN_BLOCKED,
      role,
      login,
      ip,
      userAgent,
      success: false,
      metadata: { 
        severity: 'MEDIUM',
        lockDurationMinutes,
        alert: true,
      },
    });
  }

  /**
   * Обновление токена доступа
   */
  async logTokenRefresh(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.TOKEN_REFRESH,
      userId,
      role,
      ip,
      userAgent,
      success: true,
    });
  }

  /**
   * Детекция повторного использования отозванного токена (Token Reuse Attack)
   * Это критическое событие безопасности!
   */
  async logTokenReuse(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.TOKEN_REUSE_DETECTED,
      userId,
      role,
      ip,
      userAgent,
      success: false,
      metadata: { 
        severity: 'HIGH',
        alert: true,
        action: 'all_tokens_revoked',
        description: 'Possible token theft detected. All user sessions terminated.',
      },
    });
  }

  /**
   * Выход пользователя из системы
   */
  async logLogout(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.LOGOUT,
      userId,
      role,
      ip,
      userAgent,
      success: true,
    });
  }

  /**
   * ✅ Принудительная деавторизация администратором
   */
  async logForceLogout(
    userId: number,
    role: UserRole,       // ✅ FIX: Используем enum
    adminId: number,
    adminRole: UserRole,  // ✅ FIX: Используем enum
    ip: string,
    userAgent: string,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.FORCE_LOGOUT,
      userId,
      role,
      ip,
      userAgent,
      success: true,
      metadata: {
        adminId,
        adminRole,
        reason: 'Administrative action',
      },
    });
  }

  /**
   * Доступ к профилю пользователя
   */
  async logProfileAccess(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
    cacheHit: boolean,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.PROFILE_ACCESS,
      userId,
      role,
      ip,
      userAgent,
      success: true,
      metadata: { cacheHit },
    });
  }

  /**
   * Валидация JWT токена
   */
  async logTokenValidation(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
    valid: boolean,
  ): Promise<void> {
    await this.log({
      timestamp: new Date().toISOString(),
      eventType: AuditEventType.TOKEN_VALIDATION,
      userId,
      role,
      ip,
      userAgent,
      success: valid,
    });
  }
}

