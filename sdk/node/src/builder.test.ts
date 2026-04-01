import { describe, it, expect } from 'vitest';
import { createBuilder } from './builder.js';

describe('createBuilder', () => {
  it('returns a local builder when mode is "local"', () => {
    const builder = createBuilder('local');
    expect(builder.type).toBe('local');
  });

  it('returns a remote builder when mode is a URL', () => {
    const builder = createBuilder('http://localhost:8080');
    expect(builder.type).toBe('remote');
  });
});
