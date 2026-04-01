import { describe, it, expect, beforeEach } from 'vitest';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import crypto from 'node:crypto';
import { Sigil, SigilError } from './sigil.js';
import { SQLiteStorageAdapter } from './storage/sqlite.js';
import { issueToken, verifyToken, generateToken, hashToken, generateChallenge } from './auth.js';

// Ensure sha512Sync is set for test helpers
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

describe('auth utilities', () => {
  const secret = 'test-secret-at-least-32-chars-long!!';

  it('issueToken and verifyToken round-trip', async () => {
    const payload = {
      agentId: 'agent-1',
      userId: 'user-1',
      fingerprint: 'sha256:abc',
    };
    const jwt = await issueToken(secret, payload, 60);
    expect(jwt).toBeDefined();
    expect(typeof jwt).toBe('string');

    const decoded = await verifyToken(secret, jwt);
    expect(decoded.agentId).toBe('agent-1');
    expect(decoded.userId).toBe('user-1');
    expect(decoded.fingerprint).toBe('sha256:abc');
  });

  it('verifyToken rejects invalid secret', async () => {
    const jwt = await issueToken(secret, {
      agentId: 'a',
      userId: 'u',
      fingerprint: 'f',
    }, 60);

    await expect(verifyToken('wrong-secret-that-is-also-long!!!', jwt)).rejects.toThrow();
  });

  it('generateToken returns 64-char hex string', () => {
    const token = generateToken();
    expect(token).toHaveLength(64);
    expect(token).toMatch(/^[0-9a-f]{64}$/);
  });

  it('hashToken returns deterministic SHA-256 hex', () => {
    const hash1 = hashToken('test');
    const hash2 = hashToken('test');
    expect(hash1).toBe(hash2);
    expect(hash1).toHaveLength(64);
  });

  it('generateChallenge returns base64 string', () => {
    const challenge = generateChallenge();
    expect(challenge).toBeDefined();
    // Should be valid base64
    expect(() => Buffer.from(challenge, 'base64')).not.toThrow();
    expect(Buffer.from(challenge, 'base64')).toHaveLength(32);
  });
});

describe('SigilError', () => {
  it('has code and statusCode', () => {
    const err = new SigilError('test_error', 418);
    expect(err.code).toBe('test_error');
    expect(err.statusCode).toBe(418);
    expect(err.message).toBe('test_error');
    expect(err.name).toBe('SigilError');
    expect(err).toBeInstanceOf(Error);
  });
});

describe('Sigil', () => {
  let sigil: Sigil;
  let storage: SQLiteStorageAdapter;

  beforeEach(() => {
    storage = new SQLiteStorageAdapter(':memory:');
    sigil = new Sigil({
      builder: 'local',
      platforms: ['linux-amd64', 'darwin-arm64'],
      jwtSecret: 'test-secret-at-least-32-chars-long!!',
      storage,
    });
  });

  describe('constructor defaults', () => {
    it('sets default TTLs', () => {
      expect(sigil.config.challengeTTL).toBe(30);
      expect(sigil.config.sessionTTL).toBe(300);
      expect(sigil.config.enrollmentTTL).toBe(1800);
    });

    it('allows overriding TTLs', () => {
      const custom = new Sigil({
        builder: 'local',
        platforms: ['linux-amd64'],
        jwtSecret: 'test-secret-at-least-32-chars-long!!',
        storage,
        challengeTTL: 60,
        sessionTTL: 600,
        enrollmentTTL: 3600,
      });
      expect(custom.config.challengeTTL).toBe(60);
      expect(custom.config.sessionTTL).toBe(600);
      expect(custom.config.enrollmentTTL).toBe(3600);
    });
  });

  describe('createAgent', () => {
    it('creates an agent and returns enrollment token', async () => {
      const result = await sigil.createAgent({
        name: 'test-agent',
        userId: 'user-1',
      });

      expect(result.agentId).toBeDefined();
      expect(result.enrollmentToken).toBeDefined();
      expect(result.enrollmentToken).toHaveLength(64);
      expect(result.enrollmentExpiresAt).toBeInstanceOf(Date);
      expect(result.enrollmentExpiresAt.getTime()).toBeGreaterThan(Date.now());
    });

    it('stores the agent in pending_enrollment status', async () => {
      const { agentId } = await sigil.createAgent({
        name: 'test-agent',
        userId: 'user-1',
      });

      const agent = await storage.agents.get(agentId);
      expect(agent).not.toBeNull();
      expect(agent!.name).toBe('test-agent');
      expect(agent!.externalUserId).toBe('user-1');
      expect(agent!.status).toBe('pending_enrollment');
      expect(agent!.publicKey).toBeNull();
    });

    it('stores a valid enrollment token', async () => {
      const { enrollmentToken } = await sigil.createAgent({
        name: 'test-agent',
        userId: 'user-1',
      });

      const tokenRecord = await storage.enrollmentTokens.validate(hashToken(enrollmentToken));
      expect(tokenRecord).not.toBeNull();
      expect(tokenRecord!.used).toBe(false);
    });
  });

  describe('challenge', () => {
    it('issues a challenge for an active agent', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      const result = await sigil.challenge(agentId);
      expect(result.challenge).toBeDefined();
      expect(result.expiresIn).toBe(30);
    });

    it('rejects challenge for unknown agent', async () => {
      await expect(sigil.challenge('nonexistent')).rejects.toThrow(SigilError);
      try {
        await sigil.challenge('nonexistent');
      } catch (err) {
        expect((err as SigilError).code).toBe('agent_not_found');
        expect((err as SigilError).statusCode).toBe(404);
      }
    });

    it('rejects challenge for pending agent', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });

      await expect(sigil.challenge(agentId)).rejects.toThrow(SigilError);
      try {
        await sigil.challenge(agentId);
      } catch (err) {
        expect((err as SigilError).code).toBe('agent_not_active');
        expect((err as SigilError).statusCode).toBe(403);
      }
    });

    it('rejects challenge for revoked agent', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'revoked');

      await expect(sigil.challenge(agentId)).rejects.toThrow(SigilError);
      try {
        await sigil.challenge(agentId);
      } catch (err) {
        expect((err as SigilError).code).toBe('agent_revoked');
        expect((err as SigilError).statusCode).toBe(403);
      }
    });
  });

  describe('verify', () => {
    it('verifies a valid Ed25519 signature and returns JWT', async () => {
      // Set up an agent with a known keypair
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      const privKey = ed.utils.randomPrivateKey();
      const pubKey = await ed.getPublicKeyAsync(privKey);
      const fingerprint =
        'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');

      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.from(pubKey),
        keyFingerprint: fingerprint,
      });

      // Get a challenge
      const { challenge } = await sigil.challenge(agentId);

      // Sign the challenge (message is the raw challenge bytes)
      const message = Buffer.from(challenge, 'base64');
      const signature = await ed.signAsync(message, privKey);
      const signatureB64 = Buffer.from(signature).toString('base64');

      // Verify
      const result = await sigil.verify(agentId, challenge, signatureB64);
      expect(result.token).toBeDefined();
      expect(typeof result.token).toBe('string');
      expect(result.expiresIn).toBe(300);

      // The JWT should decode correctly
      const decoded = await sigil.verifyJWT(result.token);
      expect(decoded.agentId).toBe(agentId);
      expect(decoded.userId).toBe('user-1');
      expect(decoded.fingerprint).toBe(fingerprint);
    });

    it('rejects an invalid signature', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      const privKey = ed.utils.randomPrivateKey();
      const pubKey = await ed.getPublicKeyAsync(privKey);
      const fingerprint =
        'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');

      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.from(pubKey),
        keyFingerprint: fingerprint,
      });

      const { challenge } = await sigil.challenge(agentId);

      // Sign with a different key
      const wrongKey = ed.utils.randomPrivateKey();
      const message = Buffer.from(challenge, 'base64');
      const badSignature = await ed.signAsync(message, wrongKey);
      const badSigB64 = Buffer.from(badSignature).toString('base64');

      await expect(sigil.verify(agentId, challenge, badSigB64)).rejects.toThrow(SigilError);
      try {
        // Need a new challenge since the previous one was burned by the failed verify attempt
        // Actually, verify only burns on success, and the first call threw, so let's get a fresh challenge
        const { challenge: c2 } = await sigil.challenge(agentId);
        const msg2 = Buffer.from(c2, 'base64');
        const badSig2 = await ed.signAsync(msg2, wrongKey);
        await sigil.verify(agentId, c2, Buffer.from(badSig2).toString('base64'));
      } catch (err) {
        expect((err as SigilError).code).toBe('signature_invalid');
        expect((err as SigilError).statusCode).toBe(401);
      }
    });

    it('rejects expired/unknown challenge', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      await expect(
        sigil.verify(agentId, 'nonexistent-challenge', 'fakesig'),
      ).rejects.toThrow(SigilError);
    });

    it('rejects challenge belonging to a different agent', async () => {
      const { agentId: agent1 } = await sigil.createAgent({ name: 'agent-1', userId: 'user-1' });
      const { agentId: agent2 } = await sigil.createAgent({ name: 'agent-2', userId: 'user-2' });

      await storage.agents.updateStatus(agent1, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test1',
      });
      await storage.agents.updateStatus(agent2, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test2',
      });

      const { challenge } = await sigil.challenge(agent1);

      // Try to verify with agent2's id but agent1's challenge
      await expect(
        sigil.verify(agent2, challenge, 'fakesig'),
      ).rejects.toThrow(SigilError);
    });
  });

  describe('rotate', () => {
    it('sets agent to rotating and returns new enrollment token', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      const result = await sigil.rotate(agentId);
      expect(result.enrollmentToken).toBeDefined();
      expect(result.enrollmentToken).toHaveLength(64);
      expect(result.expiresAt).toBeInstanceOf(Date);

      const agent = await storage.agents.get(agentId);
      expect(agent!.status).toBe('rotating');
    });

    it('throws for unknown agent', async () => {
      await expect(sigil.rotate('nonexistent')).rejects.toThrow(SigilError);
    });
  });

  describe('revoke', () => {
    it('sets agent to revoked and clears keys', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      await sigil.revoke(agentId);

      const agent = await storage.agents.get(agentId);
      expect(agent!.status).toBe('revoked');
      expect(agent!.publicKey).toBeNull();
      expect(agent!.keyFingerprint).toBeNull();
    });

    it('throws for unknown agent', async () => {
      await expect(sigil.revoke('nonexistent')).rejects.toThrow(SigilError);
    });
  });

  describe('reEnroll', () => {
    it('generates new enrollment token for revoked agent', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });
      await sigil.revoke(agentId);

      const result = await sigil.reEnroll(agentId);
      expect(result.enrollmentToken).toBeDefined();
      expect(result.enrollmentToken).toHaveLength(64);
      expect(result.expiresAt).toBeInstanceOf(Date);

      const agent = await storage.agents.get(agentId);
      expect(agent!.status).toBe('pending_enrollment');
    });

    it('rejects re-enroll for non-revoked agent', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.alloc(32),
        keyFingerprint: 'sha256:test',
      });

      await expect(sigil.reEnroll(agentId)).rejects.toThrow(SigilError);
      try {
        await sigil.reEnroll(agentId);
      } catch (err) {
        expect((err as SigilError).code).toBe('agent_not_revoked');
        expect((err as SigilError).statusCode).toBe(400);
      }
    });

    it('throws for unknown agent', async () => {
      await expect(sigil.reEnroll('nonexistent')).rejects.toThrow(SigilError);
    });
  });

  describe('full lifecycle: create -> rotate -> revoke -> reEnroll', () => {
    it('completes the full agent lifecycle', async () => {
      // 1. Create agent
      const { agentId, enrollmentToken } = await sigil.createAgent({
        name: 'lifecycle-agent',
        userId: 'user-lifecycle',
      });
      const agent1 = await storage.agents.get(agentId);
      expect(agent1!.status).toBe('pending_enrollment');

      // 2. Simulate enrollment by manually activating
      const privKey = ed.utils.randomPrivateKey();
      const pubKey = await ed.getPublicKeyAsync(privKey);
      const fingerprint =
        'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');
      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.from(pubKey),
        keyFingerprint: fingerprint,
        platform: 'linux-amd64',
        enrolledAt: new Date(),
      });
      // Burn the enrollment token
      await storage.enrollmentTokens.burn(hashToken(enrollmentToken));

      // 3. Challenge + Verify
      const { challenge } = await sigil.challenge(agentId);
      const message = Buffer.from(challenge, 'base64');
      const signature = await ed.signAsync(message, privKey);
      const { token } = await sigil.verify(
        agentId,
        challenge,
        Buffer.from(signature).toString('base64'),
      );

      // Verify the JWT
      const decoded = await sigil.verifyJWT(token);
      expect(decoded.agentId).toBe(agentId);
      expect(decoded.userId).toBe('user-lifecycle');

      // 4. Rotate
      const rotateResult = await sigil.rotate(agentId);
      expect(rotateResult.enrollmentToken).toBeDefined();
      const agent3 = await storage.agents.get(agentId);
      expect(agent3!.status).toBe('rotating');

      // 5. Revoke
      await sigil.revoke(agentId);
      const agent4 = await storage.agents.get(agentId);
      expect(agent4!.status).toBe('revoked');
      expect(agent4!.publicKey).toBeNull();

      // 6. Re-enroll
      const reEnrollResult = await sigil.reEnroll(agentId);
      expect(reEnrollResult.enrollmentToken).toBeDefined();
      const agent5 = await storage.agents.get(agentId);
      expect(agent5!.status).toBe('pending_enrollment');
    });
  });

  describe('verifyJWT', () => {
    it('decodes a valid JWT', async () => {
      const { agentId } = await sigil.createAgent({ name: 'test', userId: 'user-1' });
      const privKey = ed.utils.randomPrivateKey();
      const pubKey = await ed.getPublicKeyAsync(privKey);
      const fingerprint =
        'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');

      await storage.agents.updateStatus(agentId, 'active', {
        publicKey: Buffer.from(pubKey),
        keyFingerprint: fingerprint,
      });

      const { challenge } = await sigil.challenge(agentId);
      const message = Buffer.from(challenge, 'base64');
      const signature = await ed.signAsync(message, privKey);
      const { token } = await sigil.verify(
        agentId,
        challenge,
        Buffer.from(signature).toString('base64'),
      );

      const result = await sigil.verifyJWT(token);
      expect(result.agentId).toBe(agentId);
      expect(result.userId).toBe('user-1');
      expect(result.fingerprint).toBe(fingerprint);
    });

    it('rejects a tampered JWT', async () => {
      await expect(sigil.verifyJWT('invalid.jwt.token')).rejects.toThrow();
    });
  });
});
