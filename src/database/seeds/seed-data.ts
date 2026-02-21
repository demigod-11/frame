// src/database/seeds/seed-data.ts

import { OAuthProvider } from '../../auth/enums/oauth-provider.enum';
import { UserStatus } from '../../auth/enums/user-status.enum';

export interface SeedUser {
  email: string | null;
  displayName: string | null;
  avatarUrl: string | null;
  status: UserStatus;
  oauthAccounts: SeedOAuthAccount[];
}

export interface SeedOAuthAccount {
  provider: OAuthProvider;
  providerId: string;
  providerEmail: string | null;
}

export const seedUsers: SeedUser[] = [
  // ── User 1: Google-only user ──
  {
    email: 'john.doe@gmail.com',
    displayName: 'John Doe',
    avatarUrl: 'https://lh3.googleusercontent.com/a/default-user1',
    status: UserStatus.ACTIVE,
    oauthAccounts: [
      {
        provider: OAuthProvider.GOOGLE,
        providerId: 'google-uid-001',
        providerEmail: 'john.doe@gmail.com',
      },
    ],
  },

  // ── User 2: Apple-only user ──
  {
    email: 'jane.smith@icloud.com',
    displayName: 'Jane Smith',
    avatarUrl: null, // Apple doesn't provide avatar
    status: UserStatus.ACTIVE,
    oauthAccounts: [
      {
        provider: OAuthProvider.APPLE,
        providerId: 'apple-uid-001',
        providerEmail: 'jane.smith@icloud.com',
      },
    ],
  },

  // ── User 3: Both Google and Apple linked ──
  {
    email: 'multi.provider@gmail.com',
    displayName: 'Multi Provider User',
    avatarUrl: 'https://lh3.googleusercontent.com/a/default-user3',
    status: UserStatus.ACTIVE,
    oauthAccounts: [
      {
        provider: OAuthProvider.GOOGLE,
        providerId: 'google-uid-002',
        providerEmail: 'multi.provider@gmail.com',
      },
      {
        provider: OAuthProvider.APPLE,
        providerId: 'apple-uid-002',
        providerEmail: 'multi.provider@gmail.com',
      },
    ],
  },

  // ── User 4: Apple private relay email ──
  {
    email: 'abc123def456@privaterelay.appleid.com',
    displayName: 'Apple Private User',
    avatarUrl: null,
    status: UserStatus.ACTIVE,
    oauthAccounts: [
      {
        provider: OAuthProvider.APPLE,
        providerId: 'apple-uid-003',
        providerEmail: 'abc123def456@privaterelay.appleid.com',
      },
    ],
  },

  // ── User 5: Suspended user (for testing auth rejection) ──
  {
    email: 'suspended@gmail.com',
    displayName: 'Suspended User',
    avatarUrl: null,
    status: UserStatus.SUSPENDED,
    oauthAccounts: [
      {
        provider: OAuthProvider.GOOGLE,
        providerId: 'google-uid-003',
        providerEmail: 'suspended@gmail.com',
      },
    ],
  },

  // ── User 6: User with no email (possible with Apple) ──
  {
    email: null,
    displayName: 'No Email User',
    avatarUrl: null,
    status: UserStatus.ACTIVE,
    oauthAccounts: [
      {
        provider: OAuthProvider.APPLE,
        providerId: 'apple-uid-004',
        providerEmail: null,
      },
    ],
  },
];
