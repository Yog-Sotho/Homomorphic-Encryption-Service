import { describe, expect, it } from 'vitest';
import { expectedResult, isUint16 } from './operations.js';

describe('expectedResult', () => {
  it('wraps arithmetic modulo 2^16 like FheUint16', () => {
    // Same cases as the backend's every_operation_matches_plaintext_semantics.
    expect(expectedResult('add', 40_000, 30_000)).toBe(4_464);
    expect(expectedResult('subtract', 3, 10)).toBe(65_529);
    expect(expectedResult('multiply', 300, 300)).toBe(24_464);
    expect(expectedResult('multiply', 65_535, 65_535)).toBe(1);
    expect(expectedResult('add', 65_535, 1)).toBe(0);
  });

  it('computes min and max', () => {
    expect(expectedResult('min', 9, 4)).toBe(4);
    expect(expectedResult('max', 9, 4)).toBe(9);
  });
});

describe('isUint16', () => {
  it('accepts exactly the integers 0..65535', () => {
    expect([0, 1, 65_535].every(isUint16)).toBe(true);
    expect([-1, 65_536, 1.5, Number.NaN].some(isUint16)).toBe(false);
  });
});
