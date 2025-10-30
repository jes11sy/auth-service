import { Injectable, Logger } from '@nestjs/common';
import { UserRole } from '../auth/interfaces/auth.interface';

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

  /**
   * Базовый метод логирования событий аудита
   */
  log(entry: AuditLogEntry): void {
    // JSON формат для парсинга в SIEM системах
    this.logger.log(JSON.stringify({
      ...entry,
      timestamp: entry.timestamp || new Date().toISOString(),
    }));

    // TODO: Опционально - отправка в внешние системы:
    // - await this.elasticsearchService.index({ index: 'audit-logs', body: entry });
    // - await this.lokiService.push(entry);
    // - await this.s3Service.archiveLog(entry);
  }

  /**
   * Успешный вход в систему
   */
  logLoginSuccess(
    userId: number,
    role: UserRole,
    login: string,
    ip: string,
    userAgent: string,
  ): void {
    this.log({
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
  logLoginFailed(
    login: string,
    role: UserRole,
    ip: string,
    userAgent: string,
    reason: string,
    attemptsCount?: number,
  ): void {
    this.log({
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
  logLoginBlocked(
    login: string,
    role: UserRole,
    ip: string,
    userAgent: string,
    lockDurationMinutes: number,
  ): void {
    this.log({
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
  logTokenRefresh(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): void {
    this.log({
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
  logTokenReuse(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): void {
    this.log({
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
  logLogout(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
  ): void {
    this.log({
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
   * Доступ к профилю пользователя
   */
  logProfileAccess(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
    cacheHit: boolean,
  ): void {
    this.log({
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
  logTokenValidation(
    userId: number,
    role: UserRole,
    ip: string,
    userAgent: string,
    valid: boolean,
  ): void {
    this.log({
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

