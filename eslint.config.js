// @ts-check
import eslint from '@eslint/js';
import tseslint from '@typescript-eslint/eslint-plugin';
import tsParser from '@typescript-eslint/parser';
import eslintConfigPrettier from 'eslint-config-prettier';

export default [
  {
    // Fixtures under test/fixtures/** simulate a *target* agent's own
    // (deliberately insecure, or deliberately plain-JS) code — they are
    // data Chaperone scans, not project source, so our lint rules don't
    // apply to them.
    ignores: ['dist/**', 'node_modules/**', 'test/fixtures/**'],
  },
  eslint.configs.recommended,
  {
    files: ['src/**/*.ts', 'test/**/*.ts', 'scripts/**/*.ts', '*.ts', '*.js'],
    languageOptions: {
      parser: tsParser,
      parserOptions: {
        project: './tsconfig.eslint.json',
        tsconfigRootDir: import.meta.dirname,
      },
      globals: {
        process: 'readonly',
        console: 'readonly',
        __dirname: 'readonly',
      },
    },
    plugins: {
      '@typescript-eslint': tseslint,
    },
    rules: {
      ...(tseslint.configs['recommended-type-checked']?.rules ?? {}),
      ...(tseslint.configs['strict-type-checked']?.rules ?? {}),
      '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
      '@typescript-eslint/explicit-function-return-type': 'off',
      '@typescript-eslint/restrict-template-expressions': [
        'error',
        { allowNumber: true, allowBoolean: true, allowNullish: false },
      ],
      // TypeScript's own checker already flags undefined identifiers, and
      // no-undef false-positives on ambient/global types (e.g. NodeJS.*).
      'no-undef': 'off',
    },
  },
  eslintConfigPrettier,
];
