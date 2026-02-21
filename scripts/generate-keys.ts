/* eslint-disable @typescript-eslint/explicit-function-return-type */
import { execSync } from 'node:child_process';
import { existsSync, mkdirSync } from 'node:fs';

const KEY_DIR = './keys';

function run() {
  if (!existsSync(KEY_DIR)) {
    mkdirSync(KEY_DIR);
  }

  execSync(`openssl genrsa -out ${KEY_DIR}/private.pem 2048`);
  execSync(
    `openssl rsa -in ${KEY_DIR}/private.pem -pubout -out ${KEY_DIR}/public.pem`,
  );
}

run();
