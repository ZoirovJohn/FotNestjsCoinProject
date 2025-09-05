import { Module } from '@nestjs/common';
import { ConfigModule } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { ThrottlerModule } from '@nestjs/throttler';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';

@Module({
  imports: [
    ConfigModule.forRoot({ isGlobal: true }),
    MongooseModule.forRoot(process.env.MONGO_URI!, { dbName: undefined }),
    ThrottlerModule.forRoot([{ ttl: 60_000, limit: 120 }]),
    UsersModule,
    AuthModule,
  ],
})
export class AppModule {}
