export interface OAuthUserInfo {
  providerId: string;
  email: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  rawProfile: Record<string, unknown>;
}
