// src/main.ts
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  // Security & DX
  app.use(helmet());
  app.use(cookieParser());
  app.useGlobalPipes(new ValidationPipe({ whitelist: true, transform: true }));

  app.enableCors({
    origin: process.env.WEB_ORIGIN || 'http://localhost:3000',
    credentials: true,
  });

  const port = Number(process.env.PORT) || 4000;
  const host = process.env.HOST || '0.0.0.0';

  // Plain text at GET /
  app.getHttpAdapter().get('/', (_req: any, res: any) => {
    res.setHeader?.('content-type', 'text/plain; charset=utf-8');
    res.end(`✅ Backend is running on port ${port}`);
  });

  await app.listen(port, host);
  const url = await app.getUrl();
  console.log(`✅ Backend is running on ${url} (port ${port})`);
}
bootstrap();
