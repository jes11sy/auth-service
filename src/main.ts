import { NestFactory } from '@nestjs/core';
import { ValidationPipe, Logger } from '@nestjs/common';
import { SwaggerModule, DocumentBuilder } from '@nestjs/swagger';
import { FastifyAdapter, NestFastifyApplication } from '@nestjs/platform-fastify';
import { AppModule } from './app.module';
import { PrismaService } from './modules/prisma/prisma.service';
import { RedisService } from './modules/redis/redis.service';
import * as os from 'os';

// ✅ ИСПРАВЛЕНИЕ #9: Увеличиваем Thread Pool для bcrypt (async операции)
// По умолчанию UV_THREADPOOL_SIZE = 4, увеличиваем до CPU count * 2
const cpuCount = os.cpus().length;
process.env.UV_THREADPOOL_SIZE = String(Math.max(cpuCount * 2, 8));

/**
 * ✅ ИСПРАВЛЕНИЕ VULN-004: Валидация JWT секретов1
 * Проверяем что JWT_SECRET и JWT_REFRESH_SECRET:
 * 1. Существуют
 * 2. Не пустые
 * 3. Различаются между собой
 */
function validateJwtSecrets(): void {
  const jwtSecret = process.env.JWT_SECRET;
  const jwtRefreshSecret = process.env.JWT_REFRESH_SECRET;
  const logger = new Logger('SecurityValidation');

  // Проверка наличия секретов
  if (!jwtSecret || jwtSecret.trim().length === 0) {
    logger.error('❌ JWT_SECRET is required but not set in environment variables');
    throw new Error('SECURITY ERROR: JWT_SECRET must be configured');
  }

  if (!jwtRefreshSecret || jwtRefreshSecret.trim().length === 0) {
    logger.error('❌ JWT_REFRESH_SECRET is required but not set in environment variables');
    throw new Error('SECURITY ERROR: JWT_REFRESH_SECRET must be configured');
  }

  // ✅ КРИТИЧЕСКАЯ ПРОВЕРКА: Секреты должны быть разными
  if (jwtSecret === jwtRefreshSecret) {
    logger.error('❌ SECURITY VULNERABILITY: JWT_SECRET and JWT_REFRESH_SECRET are identical!');
    logger.error('   This allows attackers to forge refresh tokens from access tokens.');
    logger.error('   Please set different values for JWT_SECRET and JWT_REFRESH_SECRET.');
    throw new Error('SECURITY ERROR: JWT_SECRET and JWT_REFRESH_SECRET must be different');
  }

  // Дополнительные проверки безопасности
  const minSecretLength = 32;
  if (jwtSecret.length < minSecretLength) {
    logger.warn(`⚠️  JWT_SECRET is too short (${jwtSecret.length} chars). Recommended: ${minSecretLength}+ chars`);
  }

  if (jwtRefreshSecret.length < minSecretLength) {
    logger.warn(`⚠️  JWT_REFRESH_SECRET is too short (${jwtRefreshSecret.length} chars). Recommended: ${minSecretLength}+ chars`);
  }

  logger.log('✅ JWT secrets validation passed');
}

/**
 * ✅ FIX: Валидация COOKIE_SECRET
 * Cookie секрет должен быть установлен отдельно от JWT секретов
 */
function validateCookieSecret(): void {
  const cookieSecret = process.env.COOKIE_SECRET;
  const jwtSecret = process.env.JWT_SECRET;
  const logger = new Logger('SecurityValidation');

  if (!cookieSecret || cookieSecret.trim().length === 0) {
    logger.warn('⚠️ COOKIE_SECRET not set. Using JWT_SECRET as fallback (not recommended for production)');
    
    if (process.env.NODE_ENV === 'production') {
      logger.error('❌ COOKIE_SECRET is required in production!');
      throw new Error('SECURITY ERROR: COOKIE_SECRET must be configured in production');
    }
  } else if (cookieSecret === jwtSecret) {
    logger.warn('⚠️ COOKIE_SECRET is identical to JWT_SECRET. Consider using different values.');
  } else {
    logger.log('✅ COOKIE_SECRET validation passed');
  }
}

async function bootstrap() {
  // ✅ Валидация секретов ПЕРЕД запуском приложения
  validateJwtSecrets();
  validateCookieSecret();

  const isProduction = process.env.NODE_ENV === 'production';
  
  // ✅ FIX #86: Фильтрация уровней логов в production
  const logLevels: ('log' | 'error' | 'warn' | 'debug' | 'verbose')[] = isProduction
    ? ['log', 'error', 'warn']
    : ['log', 'error', 'warn', 'debug', 'verbose'];

  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      logger: false,
      trustProxy: true,
      bodyLimit: 102400, // ✅ ИСПРАВЛЕНИЕ #11: 100KB вместо 10MB (auth сервис принимает только маленькие JSON)
    }),
    {
      logger: logLevels, // ✅ FIX #86: Применяем фильтрацию логов
    },
  );

  const logger = new Logger('AuthService');
  const isDevelopment = !isProduction;

  // ✅ Cookie Plugin (для httpOnly cookies)
  await app.register(require('@fastify/cookie'), {
    secret: process.env.COOKIE_SECRET || process.env.JWT_SECRET, // Для подписи cookies
  });

  // CORS Configuration
  await app.register(require('@fastify/cors'), {
    origin: (origin, cb) => {
      const allowedOrigins = process.env.CORS_ORIGIN?.split(',') || [
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:3002',
        'http://localhost:3003',
      ];

      if (!origin || allowedOrigins.includes(origin) || isDevelopment) {
        cb(null, true);
      } else {
        logger.warn(`CORS blocked: ${origin}`);
        cb(null, false);
      }
    },
    credentials: true, // ✅ ВАЖНО: разрешаем отправку cookies
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: [
      'Content-Type', 
      'Authorization', 
      'Accept', 
      'Origin',
      'X-Use-Cookies', // ✅ Новый header для переключения на cookie mode
    ],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  // Security headers
  await app.register(require('@fastify/helmet'), {
    contentSecurityPolicy: isDevelopment ? false : undefined,
    crossOriginEmbedderPolicy: false,
  });

  // ✅ ИСПРАВЛЕНИЕ: Настройка Response Compression с оптимальными параметрами
  await app.register(require('@fastify/compress'), {
    global: true,
    encodings: ['gzip', 'deflate', 'br'],
    threshold: 1024, // Сжимать только ответы больше 1KB
    
    // Brotli настройки (лучшее сжатие для современных браузеров)
    brotliOptions: {
      params: {
        // Режим оптимизирован для текста/JSON
        [require('zlib').constants.BROTLI_PARAM_MODE]: require('zlib').constants.BROTLI_MODE_TEXT,
        // Quality 4 = баланс между скоростью и степенью сжатия
        [require('zlib').constants.BROTLI_PARAM_QUALITY]: 4,
      },
    },
    
    // Gzip/Deflate настройки
    zlibOptions: {
      level: 6, // Уровень 6 = хороший баланс скорость/размер
    },
    
    // Не сжимаем уже сжатые форматы
    customTypes: /^text\/|application\/json|application\/javascript/,
    
    // Удаляем Content-Length при сжатии (будет пересчитан)
    removeContentLengthHeader: true,
  });

  // Rate limiting
  await app.register(require('@fastify/rate-limit'), {
    max: parseInt(process.env.THROTTLE_LIMIT || '100'),
    timeWindow: parseInt(process.env.THROTTLE_TTL || '60') * 1000,
  });

  // Global validation pipe
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
      transformOptions: {
        enableImplicitConversion: true,
      },
    }),
  );

  // Swagger Documentation
  const config = new DocumentBuilder()
    .setTitle('Auth Service API')
    .setDescription('Unified Authentication Microservice')
    .setVersion('1.0')
    .addBearerAuth()
    .addTag('auth', 'Authentication endpoints')
    .build();

  const document = SwaggerModule.createDocument(app, config);
  SwaggerModule.setup('api/docs', app, document);

  // API Prefix
  app.setGlobalPrefix(process.env.API_PREFIX || 'api/v1');

  const port = process.env.PORT || 5001;
  await app.listen(port, '0.0.0.0');

  logger.log(`🚀 Auth Service running on http://localhost:${port}`);
  logger.log(`📚 Swagger docs: http://localhost:${port}/api/docs`);
  logger.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  logger.log(`⚡ Fastify mode enabled`);
  logger.log(`🧵 Thread pool size: ${process.env.UV_THREADPOOL_SIZE}`);

  // ✅ ИСПРАВЛЕНИЕ #13 (partial): Graceful Shutdown
  const gracefulShutdown = async (signal: string) => {
    logger.log(`${signal} received, starting graceful shutdown...`);

    try {
      // 1. Stop accepting new connections
      await app.close();
      logger.log('✅ HTTP server closed');

      // 2. Close database connections
      const prisma = app.get(PrismaService);
      await prisma.$disconnect();
      logger.log('✅ Database disconnected');

      // 3. Close Redis connections
      const redis = app.get(RedisService);
      await redis.onModuleDestroy();
      logger.log('✅ Redis disconnected');

      logger.log('✅ Graceful shutdown complete');
      process.exit(0);
    } catch (error) {
      logger.error('❌ Error during graceful shutdown:', error);
      process.exit(1);
    }
  };

  // Listen for termination signals
  process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
  process.on('SIGINT', () => gracefulShutdown('SIGINT'));
}

bootstrap();

