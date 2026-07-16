/**
 * Abir-Guard: Quantum-Resilient Agentic Vault
 * JavaScript/TypeScript SDK
 *
 * Features:
 * - AES-256-GCM vault encryption (Node crypto or WebCrypto)
 * - ML-KEM-1024 adapter interface (provider-based with simulated fallback)
 * - ML-DSA-65 adapter interface (provider-based with simulated fallback)
 * - Browser extension messaging bridge
 */

const crypto = require('crypto');

const ALGORITHM = 'aes-256-gcm';
const KEY_LENGTH = 32;
const NONCE_LENGTH = 12;

function getSubtleCrypto() {
  if (globalThis.crypto && globalThis.crypto.subtle) {
    return globalThis.crypto.subtle;
  }
  if (crypto.webcrypto && crypto.webcrypto.subtle) {
    return crypto.webcrypto.subtle;
  }
  return null;
}

function toB64(bytes) {
  return Buffer.from(bytes).toString('base64');
}

function fromB64(value) {
  return Buffer.from(value, 'base64');
}

function timingSafeEquals(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ba.length !== bb.length) {
    return false;
  }
  return crypto.timingSafeEqual(ba, bb);
}

class PQCAdapter {
  constructor(options = {}) {
    this.provider = options.provider || null;
    this.mode = options.mode || 'auto';
    this.requirePq = options.requirePq !== undefined ? options.requirePq : true;
    if (this.requirePq && !this.provider) {
      throw new Error(
        'ML-KEM/ML-DSA provider required in strict mode. ' +
        'Set requirePq: false to allow simulated (non-quantum-safe) fallback, ' +
        'or inject a real provider via options.provider.'
      );
    }
  }

  async generateMlKemKeyPair() {
    if (this.provider && this.provider.generateMlKemKeyPair) {
      return this.provider.generateMlKemKeyPair();
    }

    // Simulated ML-KEM keypair for local deterministic testing.
    const secretKey = crypto.randomBytes(KEY_LENGTH);
    return {
      algorithm: 'ML-KEM-1024(simulated)',
      publicKey: toB64(secretKey),
      secretKey: toB64(secretKey),
      simulated: true,
    };
  }

  async encapsulate(publicKeyB64) {
    if (this.provider && this.provider.encapsulate) {
      return this.provider.encapsulate(publicKeyB64);
    }

    const publicKey = fromB64(publicKeyB64);
    const nonce = crypto.randomBytes(KEY_LENGTH);
    const sharedSecret = crypto.createHash('sha256').update(Buffer.concat([publicKey, nonce])).digest();
    return {
      algorithm: 'ML-KEM-1024(simulated)',
      ciphertext: toB64(nonce),
      sharedSecret: toB64(sharedSecret),
      simulated: true,
    };
  }

  async decapsulate(ciphertextB64, secretKeyB64) {
    if (this.provider && this.provider.decapsulate) {
      return this.provider.decapsulate(ciphertextB64, secretKeyB64);
    }

    const ciphertext = fromB64(ciphertextB64);
    const secretKey = fromB64(secretKeyB64);
    const sharedSecret = crypto.createHash('sha256').update(Buffer.concat([secretKey, ciphertext])).digest();
    return {
      algorithm: 'ML-KEM-1024(simulated)',
      sharedSecret: toB64(sharedSecret),
      simulated: true,
    };
  }

  async generateMlDsaKeyPair() {
    if (this.provider && this.provider.generateMlDsaKeyPair) {
      return this.provider.generateMlDsaKeyPair();
    }

    const secretKey = crypto.randomBytes(KEY_LENGTH);
    return {
      algorithm: 'ML-DSA-65(simulated)',
      publicKey: toB64(secretKey),
      secretKey: toB64(secretKey),
      simulated: true,
    };
  }

  async sign(data, secretKeyB64) {
    if (this.provider && this.provider.sign) {
      return this.provider.sign(data, secretKeyB64);
    }

    const secretKey = fromB64(secretKeyB64);
    const signature = crypto.createHmac('sha256', secretKey).update(Buffer.from(data)).digest();
    return {
      algorithm: 'ML-DSA-65(simulated)',
      signature: toB64(signature),
      simulated: true,
    };
  }

  async verify(data, signatureB64, publicKeyB64) {
    if (this.provider && this.provider.verify) {
      return this.provider.verify(data, signatureB64, publicKeyB64);
    }

    const publicKey = fromB64(publicKeyB64);
    const expected = crypto.createHmac('sha256', publicKey).update(Buffer.from(data)).digest();
    return timingSafeEquals(expected, fromB64(signatureB64));
  }
}

/**
 * Abir-Guard Vault
 */
class AbirGuard {
  constructor(options = {}) {
    this.keys = new Map();
    this.cache = new Map();
    this.pqc = new PQCAdapter({ requirePq: true, ...options.pqc });
  }

  /**
   * Generate a new keypair for an agent
   */
  async generateKeyPair(keyId) {
    const secret = crypto.randomBytes(KEY_LENGTH);
    const publicKey = crypto.createHash('sha256').update(secret).digest();

    this.keys.set(keyId, { publicKey, secret });

    return {
      keyId,
      publicKey: publicKey.toString('base64'),
      secret: secret.toString('base64')
    };
  }

  async _deriveAesKey(secret) {
    const hash = crypto.createHash('sha256');
    hash.update(Buffer.concat([secret, Buffer.from('Abir-Guard-PQC-2026')]));
    return hash.digest();
  }

  /**
   * Encrypt data
   */
  async encrypt(keyId, data) {
    let keyData = this.keys.get(keyId);
    if (!keyData) {
      await this.generateKeyPair(keyId);
      keyData = this.keys.get(keyId);
    }

    const nonce = crypto.randomBytes(NONCE_LENGTH);
    const aesKey = await this._deriveAesKey(keyData.secret);
    const subtle = getSubtleCrypto();

    let ciphertext;
    let authTag;

    if (subtle) {
      const key = await subtle.importKey(
        'raw',
        aesKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['encrypt']
      );
      const encrypted = Buffer.from(
        await subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, Buffer.from(data))
      );
      // WebCrypto returns ciphertext||tag where tag length is 16 bytes for AES-GCM.
      authTag = encrypted.slice(encrypted.length - 16);
      ciphertext = encrypted.slice(0, encrypted.length - 16);
    } else {
      const cipher = crypto.createCipheriv(ALGORITHM, aesKey, nonce);
      ciphertext = Buffer.concat([cipher.update(Buffer.from(data)), cipher.final()]);
      authTag = cipher.getAuthTag();
    }

    const result = {
      keyId,
      nonce: nonce.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      authTag: authTag.toString('base64')
    };

    this.cache.set(keyId, result);
    return result;
  }

  /**
   * Decrypt data
   */
  async decrypt(keyId, encrypted) {
    const keyData = this.keys.get(keyId);
    if (!keyData) {
      throw new Error(`No key found for ${keyId}`);
    }

    const nonce = Buffer.from(encrypted.nonce, 'base64');
    const ciphertext = Buffer.from(encrypted.ciphertext, 'base64');
    const authTag = Buffer.from(encrypted.authTag, 'base64');
    const aesKey = await this._deriveAesKey(keyData.secret);
    const subtle = getSubtleCrypto();

    if (subtle) {
      const key = await subtle.importKey(
        'raw',
        aesKey,
        { name: 'AES-GCM', length: 256 },
        false,
        ['decrypt']
      );
      const merged = Buffer.concat([ciphertext, authTag]);
      const plaintext = Buffer.from(
        await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, key, merged)
      );
      return plaintext.toString('utf8');
    }

    const decipher = crypto.createDecipheriv(ALGORITHM, aesKey, nonce);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString('utf8');
  }

  /**
   * Rotate key (kill switch)
   */
  async rotateKey(keyId) {
    this.keys.delete(keyId);
    this.cache.delete(keyId);
    return this.generateKeyPair(keyId);
  }

  /**
   * List all keys
   */
  listKeys() {
    return Array.from(this.keys.keys());
  }

  /**
   * Delete key
   */
  async deleteKey(keyId) {
    this.keys.delete(keyId);
    this.cache.delete(keyId);
  }

  async generateMlKemKeyPair() {
    return this.pqc.generateMlKemKeyPair();
  }

  async kemEncapsulate(publicKeyB64) {
    return this.pqc.encapsulate(publicKeyB64);
  }

  async kemDecapsulate(ciphertextB64, secretKeyB64) {
    return this.pqc.decapsulate(ciphertextB64, secretKeyB64);
  }

  async generateMlDsaKeyPair() {
    return this.pqc.generateMlDsaKeyPair();
  }

  async mlDsaSign(data, secretKeyB64) {
    return this.pqc.sign(data, secretKeyB64);
  }

  async mlDsaVerify(data, signatureB64, publicKeyB64) {
    return this.pqc.verify(data, signatureB64, publicKeyB64);
  }
}

/**
 * Browser extension bridge (Manifest V3 compatible runtime messaging).
 */
class AbirGuardBrowserExtension {
  constructor(runtimeApi) {
    this.runtimeApi = runtimeApi || (globalThis.chrome ? globalThis.chrome.runtime : null);
    if (!this.runtimeApi || typeof this.runtimeApi.sendMessage !== 'function') {
      throw new Error('Browser extension runtime API not available');
    }
  }

  async sendSecureMessage(type, payload) {
    return new Promise((resolve, reject) => {
      this.runtimeApi.sendMessage({ type, payload }, (response) => {
        if (globalThis.chrome && globalThis.chrome.runtime && globalThis.chrome.runtime.lastError) {
          reject(globalThis.chrome.runtime.lastError);
          return;
        }
        resolve(response);
      });
    });
  }
}

/**
 * MCP Server Client
 */
class AbirGuardMCP {
  constructor(port = 9090) {
    this.port = port;
    this.url = `http://localhost:${port}`;
  }

  async request(method, params) {
    const response = await fetch(this.url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        method,
        params
      })
    });

    return response.json();
  }

  async generateKeyPair(keyId) {
    return this.request('generate_key', { key_id: keyId });
  }

  async encrypt(keyId, data) {
    return this.request('encrypt', { key_id: keyId, data });
  }

  async decrypt(keyId, ciphertext) {
    return this.request('decrypt', { key_id: keyId, ciphertext });
  }
}

// CommonJS exports
module.exports = {
  AbirGuard,
  AbirGuardMCP,
  AbirGuardBrowserExtension,
  PQCAdapter,
};
module.exports.default = AbirGuard;
