import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { OAuthAccount } from './entities/oauth-account.entity';
import { RefreshToken } from './entities/refresh-token.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User, OAuthAccount, RefreshToken])],
  controllers: [],
  providers: [],
  exports: [TypeOrmModule],
})
export class AuthModule {}
