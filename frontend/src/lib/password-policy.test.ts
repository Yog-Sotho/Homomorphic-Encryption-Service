import { describe, expect, it } from 'vitest';
import { isStrongPassword } from './password-policy.js';

describe('password policy', () => {
  it('matches the backend rules', () => {
    expect(isStrongPassword('Correct-Horse-9')).toBe(true);
    expect(isStrongPassword('Ünïcödé-Pass-1')).toBe(true);
    expect(isStrongPassword('Short-1a')).toBe(false);
    expect(isStrongPassword('no-uppercase-1')).toBe(false);
    expect(isStrongPassword('NO-LOWERCASE-1')).toBe(false);
    expect(isStrongPassword('No-Digits-Here')).toBe(false);
    expect(isStrongPassword('NoSymbols123')).toBe(false);
    expect(isStrongPassword(`Aa1-${'x'.repeat(125)}`)).toBe(false);
  });
});
