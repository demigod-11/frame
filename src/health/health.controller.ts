import { Controller, Get, Logger } from '@nestjs/common';
import { ApiTags, ApiOperation, ApiResponse } from '@nestjs/swagger';
import { DataSource } from 'typeorm';
import { RedisService } from '../common/redis/redis.service';
import { JwtService } from '@nestjs/jwt';

@ApiTags('Health')
@Controller('health')
export class HealthController {
  private readonly logger = new Logger(HealthController.name);

  constructor(
    private readonly dataSource: DataSource,
    private readonly redisService: RedisService,
    private readonly jwtService: JwtService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'Health check' })
  @ApiResponse({ status: 200, description: 'Service is healthy' })
  async check(): Promise<{
    status: string;
    timestamp: string;
    services: Record<string, string>;
  }> {
    const services: Record<string, string> = {};

    // Check PostgreSQL
    try {
      await this.dataSource.query('SELECT 1');
      services.database = 'healthy';
    } catch (error) {
      services.database = 'unhealthy';
      this.logger.error('Database health check failed', error);
    }

    // Check Redis
    try {
      const pong = await this.redisService.ping();
      services.redis = pong ? 'healthy' : 'unhealthy';
    } catch (error) {
      services.redis = 'unhealthy';
      this.logger.error('Redis health check failed', error);
    }

    const allHealthy = Object.values(services).every((s) => s === 'healthy');

    return {
      status: allHealthy ? 'healthy' : 'degraded',
      timestamp: new Date().toISOString(),
      services,
    };
  }

  // add a temporary JWT test endpoint for development purposes to verify that JWT signing and verification works correctly. This can be removed in production.
  @Get('jwt-test')
  @ApiOperation({ summary: 'Test JWT signing & verification (DEV ONLY)' })
  async jwtTest(): Promise<{
    signed: boolean;
    verified: boolean;
    payload: Record<string, unknown>;
  }> {
    const testPayload = {
      sub: 'test-user-id',
      email: 'test@example.com',
      type: 'access',
    };

    const token = await this.jwtService.signAsync(testPayload, {
      expiresIn: 60,
    });

    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    const decoded = await this.jwtService.verifyAsync(token);

    return {
      signed: !!token,
      verified: !!decoded,
      payload: decoded as Record<string, unknown>,
    };
  }
}
