import { plainToInstance } from 'class-transformer';
import {
  IsEnum,
  IsNotEmpty,
  IsNumber,
  IsOptional,
  IsString,
  Max,
  Min,
  validateSync,
} from 'class-validator';

enum Environment {
  Development = 'development',
  Staging = 'staging',
  Production = 'production',
  Test = 'test',
}

class EnvironmentVariables {
  @IsEnum(Environment)
  NODE_ENV: Environment = Environment.Development;

  @IsNumber()
  @Min(1)
  @Max(65535)
  PORT: number = 3000;

  @IsString()
  @IsNotEmpty()
  API_PREFIX: string = 'v1';

  // ── Database ──
  @IsString()
  @IsNotEmpty()
  DB_HOST: string = 'localhost';

  @IsNumber()
  DB_PORT: number = 5432;

  @IsString()
  @IsNotEmpty()
  DB_USERNAME: string = '';

  @IsString()
  @IsNotEmpty()
  DB_PASSWORD: string = '';

  @IsString()
  @IsNotEmpty()
  DB_NAME: string = '';

  @IsNumber()
  @IsOptional()
  DB_POOL_MAX: number = 50;

  @IsNumber()
  @IsOptional()
  DB_POOL_MIN: number = 5;

  // ── Redis ──
  @IsString()
  @IsNotEmpty()
  REDIS_HOST: string = 'localhost';

  @IsNumber()
  REDIS_PORT: number = 6379;

  @IsOptional()
  @IsString()
  REDIS_PASSWORD?: string;

  // ── JWT ──
  @IsString()
  @IsNotEmpty()
  JWT_PRIVATE_KEY_PATH: string = '';

  @IsString()
  @IsNotEmpty()
  JWT_PUBLIC_KEY_PATH: string = '';

  @IsNumber()
  JWT_ACCESS_TOKEN_TTL: number = 3600;

  @IsNumber()
  JWT_REFRESH_TOKEN_TTL: number = 2592000;

  @IsString()
  @IsNotEmpty()
  GOOGLE_CLIENT_ID: string = '';

  @IsString()
  @IsNotEmpty()
  APPLE_CLIENT_ID: string = '';

  @IsString()
  @IsNotEmpty()
  ENCRYPTION_KEY: string = '';

  @IsNumber()
  THROTTLE_TTL: number = 60;

  @IsNumber()
  THROTTLE_LIMIT: number = 10;

  @IsString()
  @IsOptional()
  CORS_ORIGINS?: string;
}

export function validate(
  config: Record<string, unknown>,
): EnvironmentVariables {
  const validatedConfig = plainToInstance(EnvironmentVariables, config, {
    enableImplicitConversion: true,
  });

  const errors = validateSync(validatedConfig, {
    skipMissingProperties: false,
    whitelist: true,
  });

  if (errors.length > 0) {
    const errorMessages = errors
      .map((err) => {
        const constraints = err.constraints
          ? Object.values(err.constraints).join(', ')
          : 'unknown error';
        return `  - ${err.property}: ${constraints}`;
      })
      .join('\n');

    throw new Error(
      `\n\n🚨 Environment validation failed:\n${errorMessages}\n\nPlease check your .env file.\n`,
    );
  }

  return validatedConfig;
}
