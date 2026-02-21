import {
  Entity,
  PrimaryGeneratedColumn,
  Column,
  CreateDateColumn,
  UpdateDateColumn,
  ManyToOne,
  JoinColumn,
  Index,
  Unique,
} from 'typeorm';
import { User } from './user.entity';
import { OAuthProvider } from '../enums/oauth-provider.enum';
import { encryptedTransformer } from '../../common/utils/encryption.util';

@Entity('oauth_accounts')
@Unique('uq_oauth_provider_id', ['provider', 'providerId'])
export class OAuthAccount {
  @PrimaryGeneratedColumn('uuid')
  id: string;

  @Index('idx_oauth_user_id')
  @Column({ name: 'user_id', type: 'uuid' })
  userId: string;

  @ManyToOne(() => User, (user) => user.oauthAccounts, {
    onDelete: 'CASCADE',
  })
  @JoinColumn({ name: 'user_id' })
  user: User;

  @Column({
    type: 'varchar',
    length: 20,
  })
  provider: OAuthProvider;

  @Column({
    name: 'provider_id',
    type: 'varchar',
    length: 255,
  })
  providerId: string;

  @Column({
    name: 'provider_email',
    type: 'varchar',
    length: 255,
    nullable: true,
  })
  providerEmail: string | null;

  @Column({
    name: 'access_token',
    type: 'text',
    nullable: true,
    transformer: encryptedTransformer,
  })
  accessToken: string | null;

  @Column({
    name: 'raw_profile',
    type: 'jsonb',
    nullable: true,
  })
  rawProfile: Record<string, unknown> | null;

  @CreateDateColumn({
    name: 'created_at',
    type: 'timestamptz',
  })
  createdAt: Date;

  @UpdateDateColumn({
    name: 'updated_at',
    type: 'timestamptz',
  })
  updatedAt: Date;
}
