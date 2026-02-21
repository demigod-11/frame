import { EncryptionUtil } from '../encryption.util';

describe('EncryptionUtil', () => {
  // Valid 32-byte key (64 hex characters)
  const testKey =
    'a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2';

  describe('encrypt', () => {
    it('should return a string in iv:ciphertext format', () => {
      const result = EncryptionUtil.encrypt('hello', testKey);
      const parts = result.split(':');

      expect(parts).toHaveLength(2);
      // IV should be 32 hex chars (16 bytes)
      expect(parts[0]).toHaveLength(32);
      // Ciphertext should be non-empty hex
      expect(parts[1].length).toBeGreaterThan(0);
    });

    it('should produce different ciphertexts for the same plaintext', () => {
      const encrypted1 = EncryptionUtil.encrypt('same-input', testKey);
      const encrypted2 = EncryptionUtil.encrypt('same-input', testKey);

      // Random IV means different output each time
      expect(encrypted1).not.toBe(encrypted2);
    });
  });

  describe('decrypt', () => {
    it('should decrypt back to original plaintext', () => {
      const plaintext = 'oauth-access-token-abc123';
      const encrypted = EncryptionUtil.encrypt(plaintext, testKey);
      const decrypted = EncryptionUtil.decrypt(encrypted, testKey);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle empty string', () => {
      const encrypted = EncryptionUtil.encrypt('', testKey);
      const decrypted = EncryptionUtil.decrypt(encrypted, testKey);

      expect(decrypted).toBe('');
    });

    it('should handle special characters and JSON', () => {
      const plaintext =
        '{"token": "eyJhbGciOiJSUzI1NiIs", "scope": "email profile"}';
      const encrypted = EncryptionUtil.encrypt(plaintext, testKey);
      const decrypted = EncryptionUtil.decrypt(encrypted, testKey);

      expect(decrypted).toBe(plaintext);
    });

    it('should handle long strings (OAuth tokens can be large)', () => {
      const plaintext = 'a'.repeat(5000);
      const encrypted = EncryptionUtil.encrypt(plaintext, testKey);
      const decrypted = EncryptionUtil.decrypt(encrypted, testKey);

      expect(decrypted).toBe(plaintext);
    });
  });

  describe('error handling', () => {
    it('should throw on invalid encrypted format (no separator)', () => {
      expect(() => {
        EncryptionUtil.decrypt('invalid-no-separator', testKey);
      }).toThrow('Invalid encrypted text format');
    });

    it('should throw on invalid encrypted format (empty parts)', () => {
      expect(() => {
        EncryptionUtil.decrypt(':', testKey);
      }).toThrow('Invalid encrypted text format');
    });

    it('should throw when decrypting with wrong key', () => {
      const encrypted = EncryptionUtil.encrypt('secret', testKey);
      const wrongKey =
        'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

      expect(() => {
        EncryptionUtil.decrypt(encrypted, wrongKey);
      }).toThrow();
    });

    it('should throw on corrupted ciphertext', () => {
      const encrypted = EncryptionUtil.encrypt('secret', testKey);
      const parts = encrypted.split(':');
      const corrupted = `${parts[0]}:${parts[1]}ff`; // Append extra chars

      expect(() => {
        EncryptionUtil.decrypt(corrupted, testKey);
      }).toThrow();
    });
  });
});
