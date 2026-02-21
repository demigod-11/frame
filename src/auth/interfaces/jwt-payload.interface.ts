export interface JwtPayload {
  sub: string;
  email: string | null;
  type: 'access' | 'refresh';
  jti?: string;
  family?: string;
  iat?: number;
  exp?: number;
}
