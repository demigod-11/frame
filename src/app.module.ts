/* eslint-disable @typescript-eslint/no-unsafe-return */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
import { Module } from '@nestjs/common';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { TypeOrmModule } from '@nestjs/typeorm';
import { JwtModule } from '@nestjs/jwt';
import { AppService } from './app.service';

import {
  databaseConfig,
  redisConfig,
  jwtConfig,
  validate,
} from './common/config';
import { JwtConfig } from './common/config/jwt.config';

import { RedisModule } from './common/redis/redis.module';
import { HealthModule } from './health/health.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      load: [databaseConfig, redisConfig, jwtConfig],
      validate,
      envFilePath: ['.env'],
    }),
    TypeOrmModule.forRootAsync({
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const dbConfig = configService.get('database');
        if (!dbConfig) {
          throw new Error('Database configuration not found');
        }
        return dbConfig;
      },
    }),
    JwtModule.registerAsync({
      global: true,
      imports: [ConfigModule],
      inject: [ConfigService],
      useFactory: (configService: ConfigService) => {
        const jwt = configService.get<JwtConfig>('jwt');
        if (!jwt) throw new Error('JWT configuration not found');
        return {
          privateKey: jwt.privateKey,
          publicKey: jwt.publicKey,
          signOptions: {
            algorithm: jwt.algorithm,
            issuer: jwt.issuer,
          },
          verifyOptions: {
            algorithms: [jwt.algorithm],
            issuer: jwt.issuer,
          },
        };
      },
    }),

    RedisModule,
    HealthModule,
  ],
  controllers: [],
  providers: [AppService],
})
export class AppModule {}
