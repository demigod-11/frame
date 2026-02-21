import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';
import { ValueTransformer } from 'typeorm';

export class EncryptionUtil {
  private static readonly ALGORITHM = 'aes-256-cbc';
  private static readonly IV_LENGTH = 16;

  /**
   * Encrypt a plaintext string using AES-256-CBC.
   * Returns: iv:encrypted (hex encoded)
   */
  static encrypt(text: string, keyHex: string): string {
    const key = Buffer.from(keyHex, 'hex');
    const iv = randomBytes(this.IV_LENGTH);
    const cipher = createCipheriv(this.ALGORITHM, key, iv);

    let encrypted = cipher.update(text, 'utf8', 'hex');
    encrypted += cipher.final('hex');

    return `${iv.toString('hex')}:${encrypted}`;
  }

  /**
   * Decrypt an encrypted string (iv:encrypted format).
   */
  static decrypt(encryptedText: string, keyHex: string): string {
    const [ivHex, encrypted] = encryptedText.split(':');

    if (!ivHex || !encrypted) {
      throw new Error('Invalid encrypted text format');
    }

    const key = Buffer.from(keyHex, 'hex');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = createDecipheriv(this.ALGORITHM, key, iv);

    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');

    return decrypted;
  }
}

/**
 * TypeORM Value Transformer for transparent field encryption.
 * Reads ENCRYPTION_KEY from process.env.
 */
export const encryptedTransformer: ValueTransformer = {
  to: (value: string | null): string | null => {
    if (!value) return null;
    const key = process.env.ENCRYPTION_KEY;
    if (!key) {
      throw new Error('ENCRYPTION_KEY not set in environment');
    }
    return EncryptionUtil.encrypt(value, key);
  },
  from: (value: string | null): string | null => {
    if (!value) return null;
    const key = process.env.ENCRYPTION_KEY;
    if (!key) {
      throw new Error('ENCRYPTION_KEY not set in environment');
    }
    try {
      return EncryptionUtil.decrypt(value, key);
    } catch {
      // If decryption fails, return the raw value (migration safety)
      return value;
    }
  },
};
