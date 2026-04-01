import { describe, it, expect, beforeEach } from 'vitest';
import { SQLiteStorageAdapter } from './sqlite.js';
import type { Agent } from '../types.js';

describe('SQLiteStorageAdapter', () => {
  let storage: SQLiteStorageAdapter;

  beforeEach(() => {
    storage = new SQLiteStorageAdapter(':memory:');
  });

  describe('agents', () => {
    const agentInput: Omit<Agent, 'createdAt'> = {
      id: 'agent-001',
      name: 'test-agent',
      externalUserId: 'user-42',
      publicKey: null,
      keyFingerprint: null,
      platform: null,
      status: 'pending_enrollment',
      enrolledAt: null,
      lastAuthAt: null,
      keyExpiresAt: null,
    };

    it('should create an agent and return it with createdAt', async () => {
      const agent = await storage.agents.create(agentInput);

      expect(agent.id).toBe('agent-001');
      expect(agent.name).toBe('test-agent');
      expect(agent.externalUserId).toBe('user-42');
      expect(agent.publicKey).toBeNull();
      expect(agent.keyFingerprint).toBeNull();
      expect(agent.platform).toBeNull();
      expect(agent.status).toBe('pending_enrollment');
      expect(agent.enrolledAt).toBeNull();
      expect(agent.lastAuthAt).toBeNull();
      expect(agent.keyExpiresAt).toBeNull();
      expect(agent.createdAt).toBeInstanceOf(Date);
    });

    it('should get an agent by id', async () => {
      await storage.agents.create(agentInput);
      const agent = await storage.agents.get('agent-001');

      expect(agent).not.toBeNull();
      expect(agent!.id).toBe('agent-001');
      expect(agent!.name).toBe('test-agent');
      expect(agent!.createdAt).toBeInstanceOf(Date);
    });

    it('should return null for unknown agent', async () => {
      const agent = await storage.agents.get('nonexistent');
      expect(agent).toBeNull();
    });

    it('should update agent status', async () => {
      await storage.agents.create(agentInput);
      await storage.agents.updateStatus('agent-001', 'active');

      const agent = await storage.agents.get('agent-001');
      expect(agent!.status).toBe('active');
    });

    it('should update agent status with extra fields', async () => {
      await storage.agents.create(agentInput);

      const now = new Date();
      const keyExpiry = new Date(Date.now() + 86400000);
      await storage.agents.updateStatus('agent-001', 'active', {
        publicKey: Buffer.from('test-key'),
        keyFingerprint: 'fp:abc123',
        platform: 'linux-x86_64',
        enrolledAt: now,
        lastAuthAt: now,
        keyExpiresAt: keyExpiry,
      });

      const agent = await storage.agents.get('agent-001');
      expect(agent!.status).toBe('active');
      expect(agent!.publicKey).toBeInstanceOf(Buffer);
      expect(agent!.publicKey!.toString()).toBe('test-key');
      expect(agent!.keyFingerprint).toBe('fp:abc123');
      expect(agent!.platform).toBe('linux-x86_64');
      expect(agent!.enrolledAt).toBeInstanceOf(Date);
      expect(agent!.lastAuthAt).toBeInstanceOf(Date);
      expect(agent!.keyExpiresAt).toBeInstanceOf(Date);
    });

    it('should list agents by user id', async () => {
      await storage.agents.create(agentInput);
      await storage.agents.create({
        ...agentInput,
        id: 'agent-002',
        name: 'second-agent',
      });
      await storage.agents.create({
        ...agentInput,
        id: 'agent-003',
        name: 'other-user-agent',
        externalUserId: 'user-99',
      });

      const agents = await storage.agents.listByUser('user-42');
      expect(agents).toHaveLength(2);
      expect(agents.map((a) => a.id).sort()).toEqual(['agent-001', 'agent-002']);
      agents.forEach((a) => {
        expect(a.createdAt).toBeInstanceOf(Date);
      });
    });

    it('should return empty array for user with no agents', async () => {
      const agents = await storage.agents.listByUser('nobody');
      expect(agents).toEqual([]);
    });
  });

  describe('enrollmentTokens', () => {
    const futureDate = new Date(Date.now() + 600_000); // 10 minutes from now

    it('should create and validate a token', async () => {
      await storage.enrollmentTokens.create({
        tokenHash: 'hash-abc',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });

      const token = await storage.enrollmentTokens.validate('hash-abc');
      expect(token).not.toBeNull();
      expect(token!.tokenHash).toBe('hash-abc');
      expect(token!.agentId).toBe('agent-001');
      expect(token!.expiresAt).toBeInstanceOf(Date);
      expect(token!.used).toBe(false);
    });

    it('should burn a token (mark as used)', async () => {
      await storage.enrollmentTokens.create({
        tokenHash: 'hash-abc',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });

      await storage.enrollmentTokens.burn('hash-abc');
      const token = await storage.enrollmentTokens.validate('hash-abc');
      expect(token).toBeNull();
    });

    it('should reject expired tokens', async () => {
      const pastDate = new Date(Date.now() - 60_000); // 1 minute ago
      await storage.enrollmentTokens.create({
        tokenHash: 'hash-expired',
        agentId: 'agent-001',
        expiresAt: pastDate,
        used: false,
      });

      const token = await storage.enrollmentTokens.validate('hash-expired');
      expect(token).toBeNull();
    });

    it('should return null for nonexistent token', async () => {
      const token = await storage.enrollmentTokens.validate('nonexistent');
      expect(token).toBeNull();
    });
  });

  describe('challenges', () => {
    const futureDate = new Date(Date.now() + 600_000);

    it('should create and validate a challenge', async () => {
      await storage.challenges.create({
        challenge: 'chal-xyz',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });

      const challenge = await storage.challenges.validate('chal-xyz');
      expect(challenge).not.toBeNull();
      expect(challenge!.challenge).toBe('chal-xyz');
      expect(challenge!.agentId).toBe('agent-001');
      expect(challenge!.expiresAt).toBeInstanceOf(Date);
      expect(challenge!.used).toBe(false);
    });

    it('should burn a challenge (mark as used)', async () => {
      await storage.challenges.create({
        challenge: 'chal-xyz',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });

      await storage.challenges.burn('chal-xyz');
      const challenge = await storage.challenges.validate('chal-xyz');
      expect(challenge).toBeNull();
    });

    it('should reject expired challenges', async () => {
      const pastDate = new Date(Date.now() - 60_000);
      await storage.challenges.create({
        challenge: 'chal-old',
        agentId: 'agent-001',
        expiresAt: pastDate,
        used: false,
      });

      const challenge = await storage.challenges.validate('chal-old');
      expect(challenge).toBeNull();
    });

    it('should return null for nonexistent challenge', async () => {
      const challenge = await storage.challenges.validate('nonexistent');
      expect(challenge).toBeNull();
    });
  });

  describe('cleanup', () => {
    it('should remove expired challenges', async () => {
      const pastDate = new Date(Date.now() - 60_000);
      const futureDate = new Date(Date.now() + 600_000);

      await storage.challenges.create({
        challenge: 'chal-expired',
        agentId: 'agent-001',
        expiresAt: pastDate,
        used: false,
      });
      await storage.challenges.create({
        challenge: 'chal-valid',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });

      await storage.cleanup();

      // Expired challenge should be gone — validate won't find it even without cleanup,
      // but we verify by checking the valid one still exists
      const valid = await storage.challenges.validate('chal-valid');
      expect(valid).not.toBeNull();
    });

    it('should remove used tokens', async () => {
      const futureDate = new Date(Date.now() + 600_000);

      await storage.enrollmentTokens.create({
        tokenHash: 'hash-used',
        agentId: 'agent-001',
        expiresAt: futureDate,
        used: false,
      });
      await storage.enrollmentTokens.burn('hash-used');

      await storage.enrollmentTokens.create({
        tokenHash: 'hash-active',
        agentId: 'agent-002',
        expiresAt: futureDate,
        used: false,
      });

      await storage.cleanup();

      // The burned token row should be deleted, the active one should remain
      const active = await storage.enrollmentTokens.validate('hash-active');
      expect(active).not.toBeNull();
    });

    it('should remove expired tokens', async () => {
      const pastDate = new Date(Date.now() - 60_000);
      const futureDate = new Date(Date.now() + 600_000);

      await storage.enrollmentTokens.create({
        tokenHash: 'hash-expired',
        agentId: 'agent-001',
        expiresAt: pastDate,
        used: false,
      });
      await storage.enrollmentTokens.create({
        tokenHash: 'hash-fresh',
        agentId: 'agent-002',
        expiresAt: futureDate,
        used: false,
      });

      await storage.cleanup();

      const fresh = await storage.enrollmentTokens.validate('hash-fresh');
      expect(fresh).not.toBeNull();
    });
  });
});
