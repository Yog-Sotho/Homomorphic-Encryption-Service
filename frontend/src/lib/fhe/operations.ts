import type { Operation } from '../api.js';

export const UINT16_MAX = 0xffff;

export const OPERATIONS: { id: Operation; label: string; symbol: string }[] = [
  { id: 'add', label: 'Add', symbol: '+' },
  { id: 'subtract', label: 'Subtract', symbol: '−' },
  { id: 'multiply', label: 'Multiply', symbol: '×' },
  { id: 'min', label: 'Min', symbol: 'min' },
  { id: 'max', label: 'Max', symbol: 'max' }
];

/**
 * Plaintext result of `op(a, b)` on unsigned 16-bit integers: what the decrypted
 * homomorphic result must equal. Arithmetic wraps modulo 2^16, like FheUint16.
 */
export function expectedResult(op: Operation, a: number, b: number): number {
  switch (op) {
    case 'add':
      return (a + b) & UINT16_MAX;
    case 'subtract':
      return (a - b) & UINT16_MAX;
    case 'multiply':
      // Math.imul keeps the product exact before truncating to 16 bits.
      return Math.imul(a, b) & UINT16_MAX;
    case 'min':
      return Math.min(a, b);
    case 'max':
      return Math.max(a, b);
  }
}

export function isUint16(value: number): boolean {
  return Number.isInteger(value) && value >= 0 && value <= UINT16_MAX;
}
