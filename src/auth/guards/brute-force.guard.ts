import { Injectable, HttpException, HttpStatus, Logger } from '@nestjs/common';
import { RedisService } from '../../common/redis/redis.service';
import { AUTH } from '../constants/auth.constants';

@Injectable()
export class BruteForceGuard {
  private readonly logger = new Logger(BruteForceGuard.name);

  constructor(private readonly redisService: RedisService) {}

  /**
   * Check if an IP is blocked due to too many failed attempts.
   */
  async checkBruteForce(ip: string): Promise<void> {
    const blockKey = `${AUTH.BRUTE_FORCE_PREFIX}block:${ip}`;
    const isBlocked = await this.redisService.exists(blockKey);

    if (isBlocked) {
      this.logger.warn(`Blocked IP attempted login: ip=${ip}`);

      throw new HttpException(
        {
          code: 'AUTH_RATE_LIMIT_EXCEEDED',
          message: 'Too many failed attempts. Please try again later.',
        },
        HttpStatus.TOO_MANY_REQUESTS,
      );
    }
  }

  /**
   * Record a failed authentication attempt.
   */
  async recordFailedAttempt(ip: string): Promise<void> {
    const attemptsKey = `${AUTH.BRUTE_FORCE_PREFIX}attempts:${ip}`;
    const current = await this.redisService.get(attemptsKey);
    const attempts = current ? parseInt(current, 10) + 1 : 1;

    // Store with 15-minute window
    await this.redisService.set(attemptsKey, attempts.toString(), 900);

    if (attempts >= AUTH.BRUTE_FORCE_MAX_ATTEMPTS) {
      // Block the IP
      const blockKey = `${AUTH.BRUTE_FORCE_PREFIX}block:${ip}`;
      await this.redisService.set(
        blockKey,
        '1',
        AUTH.BRUTE_FORCE_BLOCK_DURATION,
      );

      this.logger.warn(
        `IP blocked due to brute force: ip=${ip}, attempts=${attempts}`,
      );
    }
  }

  /**
   * Reset failed attempts on successful login.
   */
  async resetAttempts(ip: string): Promise<void> {
    const attemptsKey = `${AUTH.BRUTE_FORCE_PREFIX}attempts:${ip}`;
    await this.redisService.del(attemptsKey);
  }
}
