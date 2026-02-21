module.exports = {
  // ── TypeScript files ──
  '*.ts': [
    // Run ESLint with auto-fix
    'eslint --fix --max-warnings 0',

    // Run Prettier
    'prettier --write',
  ],

  // ── JSON files (package.json, tsconfig, etc.) ──
  '*.json': [
    'prettier --write',
  ],

  // ── Markdown files ──
  '*.md': [
    'prettier --write',
  ],

  // ── YAML files (docker-compose, CI config) ──
  '*.{yml,yaml}': [
    'prettier --write',
  ],
};