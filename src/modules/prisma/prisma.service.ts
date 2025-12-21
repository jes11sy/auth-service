import { Injectable, OnModuleInit, OnModuleDestroy, Logger } from '@nestjs/common';
import { PrismaClient } from '@prisma/client';

@Injectable()
export class PrismaService extends PrismaClient implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(PrismaService.name);

  constructor() {
    const isDevelopment = process.env.NODE_ENV === 'development';
    
    // ✅ ИСПРАВЛЕНИЕ PERF-001: Connection Pool Configuration
    // Настройка connection pool через параметры URL
    const databaseUrl = process.env.DATABASE_URL || '';
    const hasParams = databaseUrl.includes('?');
    
    // ✅ ОПТИМИЗИРОВАНО: Auth Service получает много коротких запросов (логин, проверка токенов)
    // Увеличено с 10 до 25 для обработки burst нагрузки
    const connectionParams = [
      'connection_limit=25',      // Увеличено для production нагрузки
      'pool_timeout=20',          // Таймаут получения соединения: 20s
      'connect_timeout=10',       // Таймаут подключения к БД: 10s
      'socket_timeout=60',        // Таймаут socket: 60s
      // ✅ FIX: TCP Keepalive для предотвращения idle-session timeout
      'keepalives=1',
      'keepalives_idle=30',
      'keepalives_interval=10',
      'keepalives_count=3',
    ];
    
    // Проверяем наличие параметров в URL
    const needsParams = !databaseUrl.includes('connection_limit');
    const enhancedUrl = needsParams
      ? `${databaseUrl}${hasParams ? '&' : '?'}${connectionParams.join('&')}`
      : databaseUrl;

    super({
      datasources: {
        db: {
          url: enhancedUrl,
        },
      },
      log: isDevelopment 
        ? ['query', 'info', 'warn', 'error']
        : ['error'],
    });
    
    if (needsParams) {
      this.logger.log('✅ Connection pool configured: limit=25, pool_timeout=20s, connect_timeout=10s');
    }
  }

  async onModuleInit() {
    try {
      await this.$connect();
      this.logger.log('✅ Database connected successfully');
      
      // ✅ ИСПРАВЛЕНИЕ: Добавляем middleware для мониторинга производительности запросов
      this.setupQueryPerformanceMonitoring();
    } catch (error) {
      this.logger.error('❌ Failed to connect to database', error);
      throw error;
    }
  }

  /**
   * ✅ НОВОЕ: Query Performance Monitoring
   * Отслеживает медленные запросы и логирует их для оптимизации
   */
  private setupQueryPerformanceMonitoring(): void {
    this.$use(async (params, next) => {
      const startTime = Date.now();
      
      try {
        const result = await next(params);
        const duration = Date.now() - startTime;
        
        // Пороги для разных типов операций
        const SLOW_QUERY_THRESHOLD = 1000; // 1 секунда
        const WARNING_THRESHOLD = 500;     // 500 мс
        
        // Детальное логирование медленных запросов
        if (duration > SLOW_QUERY_THRESHOLD) {
          this.logger.error(
            `🐌 SLOW QUERY DETECTED: ${params.model}.${params.action} took ${duration}ms`,
            JSON.stringify({
              model: params.model,
              action: params.action,
              duration,
              args: params.args,
              timestamp: new Date().toISOString(),
            }, null, 2)
          );
        } else if (duration > WARNING_THRESHOLD) {
          this.logger.warn(
            `⚠️ Slow query: ${params.model}.${params.action} took ${duration}ms`
          );
        } else if (process.env.NODE_ENV === 'development') {
          // В dev режиме логируем все запросы для анализа
          this.logger.debug(
            `Query: ${params.model}.${params.action} - ${duration}ms`
          );
        }
        
        // TODO: Интеграция с Prometheus для метрик
        // prometheusService.recordQueryDuration(params.model, params.action, duration);
        
        return result;
      } catch (error) {
        const duration = Date.now() - startTime;
        this.logger.error(
          `❌ Query failed: ${params.model}.${params.action} after ${duration}ms`,
          error
        );
        throw error;
      }
    });
    
    this.logger.log('✅ Query performance monitoring enabled');
  }

  async onModuleDestroy() {
    await this.$disconnect();
    this.logger.log('Database disconnected');
  }
}

