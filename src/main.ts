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

async function bootstrap() {
  const app = await NestFactory.create<NestFastifyApplication>(
    AppModule,
    new FastifyAdapter({
      logger: false,
      trustProxy: true,
      bodyLimit: 102400, // ✅ ИСПРАВЛЕНИЕ #11: 100KB вместо 10MB (auth сервис принимает только маленькие JSON)
    }),
  );

  const logger = new Logger('AuthService');
  const isDevelopment = process.env.NODE_ENV !== 'production';

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
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin'],
    preflightContinue: false,
    optionsSuccessStatus: 204,
  });

  // Security headers
  await app.register(require('@fastify/helmet'), {
    contentSecurityPolicy: isDevelopment ? false : undefined,
    crossOriginEmbedderPolicy: false,
  });

  // Compression
  await app.register(require('@fastify/compress'), {
    encodings: ['gzip', 'deflate', 'br'],
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

