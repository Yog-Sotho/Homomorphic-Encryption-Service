import { describe, expect, it } from 'vitest';
import {
  INTEGER_TYPES,
  OPERATIONS,
  expectedResult,
  parsePlainValue,
  parseValue,
  resultType,
  typeRange,
  wrap
} from './operations.js';

describe('expectedResult', () => {
  it('wraps arithmetic modulo 2^bits like the server', () => {
    // Same cases as heaas-core's arithmetic_wraps_modulo_2_bits.
    expect(expectedResult('multiply', 'u16', [300n, 300n])).toBe(24_464n);
    expect(expectedResult('subtract', 'u16', [3n, 10n])).toBe(65_529n);
    expect(expectedResult('add', 'u16', [40_000n, 30_000n])).toBe(4_464n);
    expect(expectedResult('add', 'i8', [100n, 100n])).toBe(-56n);
    expect(expectedResult('multiply', 'i16', [-300n, 300n])).toBe(-24_464n);
    const max = (1n << 64n) - 1n;
    expect(expectedResult('multiply', 'u64', [max, max])).toBe(1n);
    expect(expectedResult('multiply', 'i64', [-(1n << 63n), -1n])).toBe(-(1n << 63n));
    expect(expectedResult('sum', 'u8', [200n, 100n, 1n])).toBe(45n);
  });

  it('compares with the type’s signedness and returns booleans', () => {
    expect(expectedResult('min', 'i8', [-9n, 4n])).toBe(-9n);
    expect(expectedResult('max', 'u16', [9n, 4n])).toBe(9n);
    expect(expectedResult('lt', 'i16', [-1n, 0n])).toBe(true);
    expect(expectedResult('ge', 'u8', [3n, 3n])).toBe(true);
    expect(expectedResult('gt', 'u8', [3n, 3n])).toBe(false);
    expect(expectedResult('ne', 'u8', [1n, 2n])).toBe(true);
    expect(expectedResult('eq', 'u8', [1n, 2n])).toBe(false);
    expect(expectedResult('le', 'i32', [-5n, -5n])).toBe(true);
  });

  it('decrypts comparisons as booleans', () => {
    expect(resultType('lt', 'u32')).toBe('bool');
    expect(resultType('sum', 'i8')).toBe('i8');
    expect(OPERATIONS.filter((o) => o.kind === 'comparison')).toHaveLength(6);
  });
});

describe('values', () => {
  it('parses decimal values within the type’s range only', () => {
    expect(parseValue('i16', ' -300 ')).toBe(-300n);
    expect(parseValue('u64', '18446744073709551615')).toBe((1n << 64n) - 1n);
    for (const [type, text] of [
      ['u8', '256'],
      ['u8', '-1'],
      ['i8', '1.5'],
      ['u16', ''],
      ['u16', '1e3']
    ] as const) {
      expect(parseValue(type, text)).toBeNull();
    }
  });

  it('wraps into range and knows every range', () => {
    expect(wrap('u16', 70_000n)).toBe(4_464n);
    expect(wrap('i8', 128n)).toBe(-128n);
    expect(typeRange('i8')).toEqual({ min: -128n, max: 127n });
    for (const { id } of INTEGER_TYPES) {
      const { min, max } = typeRange(id);
      expect(wrap(id, max + 1n)).toBe(min);
    }
  });

  it('reads the worker’s decrypted values', () => {
    expect(parsePlainValue('bool', 'true')).toBe(true);
    expect(parsePlainValue('bool', 'false')).toBe(false);
    expect(parsePlainValue('i64', '-9223372036854775808')).toBe(-(1n << 63n));
  });
});
