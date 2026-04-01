export interface SigilConfig {
  builder: string;
  platforms: string[];
  jwtSecret: string;
  challengeTTL?: number;
  sessionTTL?: number;
  enrollmentTTL?: number;
  storage: StorageAdapter;
  maxKeyAge?: string | null;
}

export interface Agent {
  id: string;
  name: string;
  externalUserId: string;
  publicKey: Buffer | null;
  keyFingerprint: string | null;
  platform: string | null;
  status: 'pending_enrollment' | 'active' | 'rotating' | 'revoked';
  enrolledAt: Date | null;
  lastAuthAt: Date | null;
  keyExpiresAt: Date | null;
  createdAt: Date;
}

export interface EnrollmentToken {
  tokenHash: string;
  agentId: string;
  expiresAt: Date;
  used: boolean;
}

export interface Challenge {
  challenge: string;
  agentId: string;
  expiresAt: Date;
  used: boolean;
}

export interface StorageAdapter {
  agents: {
    create(agent: Omit<Agent, 'createdAt'>): Promise<Agent>;
    get(id: string): Promise<Agent | null>;
    updateStatus(id: string, status: Agent['status'], fields?: Partial<Agent>): Promise<void>;
    listByUser(userId: string): Promise<Agent[]>;
  };
  enrollmentTokens: {
    create(token: EnrollmentToken): Promise<void>;
    validate(tokenHash: string): Promise<EnrollmentToken | null>;
    burn(tokenHash: string): Promise<void>;
  };
  challenges: {
    create(challenge: Challenge): Promise<void>;
    validate(challenge: string): Promise<Challenge | null>;
    burn(challenge: string): Promise<void>;
  };
  cleanup(): Promise<void>;
}
