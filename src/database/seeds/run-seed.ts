/* eslint-disable @typescript-eslint/no-unsafe-member-access */
/* eslint-disable @typescript-eslint/no-floating-promises */
/* eslint-disable @typescript-eslint/no-unsafe-assignment */
/* eslint-disable no-console */
import { DataSource } from 'typeorm';
import * as dotenv from 'dotenv';
import { seedUsers } from './seed-data';

dotenv.config();

async function runSeed(): Promise<void> {
  console.log('🌱 Starting database seed...\n');

  const dataSource = new DataSource({
    type: 'postgres',
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432', 10),
    username: process.env.DB_USERNAME,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    synchronize: false,
    logging: false,
  });

  await dataSource.initialize();
  console.log('✅ Database connected\n');

  const queryRunner = dataSource.createQueryRunner();

  try {
    await queryRunner.startTransaction();

    // ── Clear existing data (idempotent — safe to run multiple times) ──
    console.log('🗑️  Clearing existing seed data...');
    await queryRunner.query('DELETE FROM "refresh_tokens"');
    await queryRunner.query('DELETE FROM "oauth_accounts"');
    await queryRunner.query('DELETE FROM "users"');
    console.log('   Done.\n');

    // ── Insert users and OAuth accounts ──
    console.log('👤 Creating users...\n');

    for (const seedUser of seedUsers) {
      // Insert user
      const [user] = await queryRunner.query(
        `INSERT INTO "users" (
          "email",
          "display_name",
          "avatar_url",
          "status"
        )
        VALUES ($1, $2, $3, $4)
        RETURNING "id"`,
        [
          seedUser.email,
          seedUser.displayName,
          seedUser.avatarUrl,
          seedUser.status,
        ],
      );

      const userId: string = user.id;
      console.log(
        `   👤 ${seedUser.displayName || '(no name)'} — ${seedUser.email || '(no email)'} [${userId}]`,
      );

      // Insert OAuth accounts for this user
      for (const oa of seedUser.oauthAccounts) {
        await queryRunner.query(
          `INSERT INTO "oauth_accounts" (
            "user_id",
            "provider",
            "provider_id",
            "provider_email"
          )
          VALUES ($1, $2, $3, $4)`,
          [userId, oa.provider, oa.providerId, oa.providerEmail],
        );
        console.log(`      🔗 ${oa.provider} (${oa.providerId})`);
      }

      console.log('');
    }

    await queryRunner.commitTransaction();

    // ── Summary ──
    const [{ count: userCount }] = await queryRunner.query(
      'SELECT COUNT(*) as count FROM "users"',
    );
    const [{ count: oauthCount }] = await queryRunner.query(
      'SELECT COUNT(*) as count FROM "oauth_accounts"',
    );

    console.log('════════════════════════════════════');
    console.log(`✅ Seed complete!`);
    console.log(`   Users created:    ${userCount}`);
    console.log(`   OAuth accounts:   ${oauthCount}`);
    console.log('════════════════════════════════════\n');
  } catch (error) {
    await queryRunner.rollbackTransaction();
    console.error('\n❌ Seed failed:', error);
    process.exit(1);
  } finally {
    await queryRunner.release();
    await dataSource.destroy();
  }
}

runSeed();
