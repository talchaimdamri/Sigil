import crypto from 'node:crypto';
import * as ed from '@noble/ed25519';
import { sha512 } from '@noble/hashes/sha2.js';
import { createBuilder, type Builder } from './builder.js';
import { issueToken, verifyToken, generateToken, hashToken, generateChallenge } from './auth.js';
import type { SigilConfig, StorageAdapter, Agent } from './types.js';

// Required for synchronous Ed25519 verification in Node.js
ed.etc.sha512Sync = (...m: Uint8Array[]) => sha512(ed.etc.concatBytes(...m));

export class SigilError extends Error {
  constructor(
    public code: string,
    public statusCode: number,
  ) {
    super(code);
    this.name = 'SigilError';
  }
}

export class Sigil {
  config: SigilConfig & { challengeTTL: number; sessionTTL: number; enrollmentTTL: number };
  private builder: Builder;

  constructor(config: SigilConfig) {
    this.config = {
      challengeTTL: 30,
      sessionTTL: 300,
      enrollmentTTL: 1800,
      ...config,
    };
    this.builder = createBuilder(config.builder, { garble: config.garble, upx: config.upx });
  }

  async createAgent(params: { name: string; userId: string }): Promise<{
    agentId: string;
    enrollmentToken: string;
    enrollmentExpiresAt: Date;
  }> {
    const agentId = crypto.randomUUID();
    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.create({
      id: agentId,
      name: params.name,
      externalUserId: params.userId,
      publicKey: null,
      keyFingerprint: null,
      platform: null,
      status: 'pending_enrollment',
      enrolledAt: null,
      lastAuthAt: null,
      keyExpiresAt: null,
    });

    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { agentId, enrollmentToken: token, enrollmentExpiresAt: expiresAt };
  }

  async enroll(
    token: string,
    platform: string,
  ): Promise<{
    agentId: string;
    binary: Buffer;
    fingerprint: string;
  }> {
    if (!this.config.platforms.includes(platform)) {
      throw new SigilError('unsupported_platform', 400);
    }

    const tokenRecord = await this.config.storage.enrollmentTokens.validate(hashToken(token));
    if (!tokenRecord) {
      throw new SigilError('token_expired', 401);
    }

    const agent = await this.config.storage.agents.get(tokenRecord.agentId);
    if (!agent) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status !== 'pending_enrollment' && agent.status !== 'rotating') {
      throw new SigilError('already_enrolled', 403);
    }

    // Generate Ed25519 key pair
    const privKey = ed.utils.randomPrivateKey(); // 32-byte seed
    const pubKey = await ed.getPublicKeyAsync(privKey);
    const fingerprint = 'sha256:' + crypto.createHash('sha256').update(pubKey).digest('hex');

    // Build identity binary
    const { binary } = await this.builder.build(
      Buffer.from(privKey).toString('base64'),
      platform,
    );

    // Store public key, burn token
    await this.config.storage.agents.updateStatus(tokenRecord.agentId, 'active', {
      publicKey: Buffer.from(pubKey),
      keyFingerprint: fingerprint,
      platform,
      enrolledAt: new Date(),
    });
    await this.config.storage.enrollmentTokens.burn(tokenRecord.tokenHash);

    return { agentId: tokenRecord.agentId, binary, fingerprint };
  }

  async challenge(agentId: string): Promise<{ challenge: string; expiresIn: number }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status === 'revoked') {
      throw new SigilError('agent_revoked', 403);
    }
    if (agent.status !== 'active') {
      throw new SigilError('agent_not_active', 403);
    }

    const challenge = generateChallenge();
    await this.config.storage.challenges.create({
      challenge,
      agentId,
      expiresAt: new Date(Date.now() + this.config.challengeTTL * 1000),
      used: false,
    });

    return { challenge, expiresIn: this.config.challengeTTL };
  }

  async verify(
    agentId: string,
    challenge: string,
    signatureB64: string,
  ): Promise<{
    token: string;
    expiresIn: number;
  }> {
    const challengeRecord = await this.config.storage.challenges.validate(challenge);
    if (!challengeRecord) {
      throw new SigilError('challenge_expired', 401);
    }
    if (challengeRecord.agentId !== agentId) {
      throw new SigilError('challenge_expired', 401);
    }

    const agent = await this.config.storage.agents.get(agentId);
    if (!agent || !agent.publicKey) {
      throw new SigilError('agent_not_found', 404);
    }
    if (agent.status === 'revoked') {
      throw new SigilError('agent_revoked', 403);
    }

    const signature = Buffer.from(signatureB64, 'base64');
    const message = Buffer.from(challenge, 'base64');
    const isValid = ed.verify(signature, message, new Uint8Array(agent.publicKey));

    if (!isValid) {
      throw new SigilError('signature_invalid', 401);
    }

    await this.config.storage.challenges.burn(challenge);

    await this.config.storage.agents.updateStatus(agentId, 'active', {
      lastAuthAt: new Date(),
    });

    const token = await issueToken(
      this.config.jwtSecret,
      { agentId, userId: agent.externalUserId, fingerprint: agent.keyFingerprint! },
      this.config.sessionTTL,
    );

    return { token, expiresIn: this.config.sessionTTL };
  }

  async rotate(agentId: string): Promise<{ enrollmentToken: string; expiresAt: Date }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.updateStatus(agentId, 'rotating');
    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { enrollmentToken: token, expiresAt };
  }

  async revoke(agentId: string): Promise<void> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);

    await this.config.storage.agents.updateStatus(agentId, 'revoked', {
      publicKey: null,
      keyFingerprint: null,
    });
  }

  async reEnroll(agentId: string): Promise<{ enrollmentToken: string; expiresAt: Date }> {
    const agent = await this.config.storage.agents.get(agentId);
    if (!agent) throw new SigilError('agent_not_found', 404);
    if (agent.status !== 'revoked') throw new SigilError('agent_not_revoked', 400);

    const token = generateToken();
    const expiresAt = new Date(Date.now() + this.config.enrollmentTTL * 1000);

    await this.config.storage.agents.updateStatus(agentId, 'pending_enrollment');
    await this.config.storage.enrollmentTokens.create({
      tokenHash: hashToken(token),
      agentId,
      expiresAt,
      used: false,
    });

    return { enrollmentToken: token, expiresAt };
  }

  async verifyJWT(
    token: string,
  ): Promise<{ agentId: string; userId: string; fingerprint: string }> {
    return verifyToken(this.config.jwtSecret, token);
  }
}
