import { registerAs } from '@nestjs/config';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';

export interface JwtConfig {
  privateKey: string;
  publicKey: string;
  algorithm: 'RS256';
  issuer: string;
  accessTokenTtl?: number;
  refreshTokenTtl?: number;
}

export default registerAs('jwt', (): JwtConfig => {
  const privateKeyPath = resolve(
    process.env.JWT_PRIVATE_KEY_PATH || './keys/private.pem',
  );
  const publicKeyPath = resolve(
    process.env.JWT_PUBLIC_KEY_PATH || './keys/public.pem',
  );

  if (!existsSync(privateKeyPath)) {
    throw new Error(
      `\n JWT private key not found at: ${privateKeyPath}\n` +
        `Run: ./scripts/generate-keys.sh\n`,
    );
  }

  if (!existsSync(publicKeyPath)) {
    throw new Error(
      `\n JWT public key not found at: ${publicKeyPath}\n` +
        `Run: ./scripts/generate-keys.sh\n`,
    );
  }

  return {
    privateKey: readFileSync(privateKeyPath, 'utf8'),
    publicKey: readFileSync(publicKeyPath, 'utf8'),
    accessTokenTtl: parseInt(process.env.JWT_ACCESS_TOKEN_TTL || '3600', 10),
    refreshTokenTtl: parseInt(
      process.env.JWT_REFRESH_TOKEN_TTL || '2592000',
      10,
    ),
    algorithm: 'RS256',
    issuer: 'frame-app',
  };
});
