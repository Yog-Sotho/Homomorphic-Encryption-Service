import type { IntegerType, Operation, ValueType } from '../api.js';

/** A decrypted (or expected) value: an integer of any width, or a comparison's answer. */
export type PlainValue = bigint | boolean;

export interface TypeInfo {
  id: IntegerType;
  bits: 8 | 16 | 32 | 64;
  signed: boolean;
  /** The TFHE-rs type, e.g. FheUint16. */
  tfhe: string;
}

export const INTEGER_TYPES: TypeInfo[] = [
  { id: 'u8', bits: 8, signed: false, tfhe: 'FheUint8' },
  { id: 'u16', bits: 16, signed: false, tfhe: 'FheUint16' },
  { id: 'u32', bits: 32, signed: false, tfhe: 'FheUint32' },
  { id: 'u64', bits: 64, signed: false, tfhe: 'FheUint64' },
  { id: 'i8', bits: 8, signed: true, tfhe: 'FheInt8' },
  { id: 'i16', bits: 16, signed: true, tfhe: 'FheInt16' },
  { id: 'i32', bits: 32, signed: true, tfhe: 'FheInt32' },
  { id: 'i64', bits: 64, signed: true, tfhe: 'FheInt64' }
];

export function typeInfo(type: IntegerType): TypeInfo {
  const info = INTEGER_TYPES.find((t) => t.id === type);
  if (!info) throw new Error(`Unknown type ${type}`);
  return info;
}

export function typeRange(type: IntegerType): { min: bigint; max: bigint } {
  const { bits, signed } = typeInfo(type);
  const b = BigInt(bits);
  return signed
    ? { min: -(1n << (b - 1n)), max: (1n << (b - 1n)) - 1n }
    : { min: 0n, max: (1n << b) - 1n };
}

/** Reduces `value` modulo 2^bits into the type's range, as the encrypted arithmetic does. */
export function wrap(type: IntegerType, value: bigint): bigint {
  const { bits, signed } = typeInfo(type);
  return signed ? BigInt.asIntN(bits, value) : BigInt.asUintN(bits, value);
}

/** A decimal value in the type's range, or `null` if the text is not one. */
export function parseValue(type: IntegerType, text: string): bigint | null {
  const trimmed = text.trim();
  if (!/^-?\d+$/.test(trimmed)) return null;
  const value = BigInt(trimmed);
  const { min, max } = typeRange(type);
  return value >= min && value <= max ? value : null;
}

/** Most inputs of a sum (`max_inputs` of `/he/params`). */
export const MAX_SUM_INPUTS = 16;

export type OperationKind = 'arithmetic' | 'comparison' | 'sum';

export const OPERATIONS: { id: Operation; label: string; symbol: string; kind: OperationKind }[] = [
  { id: 'add', label: 'Add', symbol: '+', kind: 'arithmetic' },
  { id: 'subtract', label: 'Subtract', symbol: '−', kind: 'arithmetic' },
  { id: 'multiply', label: 'Multiply', symbol: '×', kind: 'arithmetic' },
  { id: 'min', label: 'Min', symbol: 'min', kind: 'arithmetic' },
  { id: 'max', label: 'Max', symbol: 'max', kind: 'arithmetic' },
  { id: 'eq', label: 'Equal', symbol: '=', kind: 'comparison' },
  { id: 'ne', label: 'Not equal', symbol: '≠', kind: 'comparison' },
  { id: 'lt', label: 'Less', symbol: '<', kind: 'comparison' },
  { id: 'le', label: 'Less or equal', symbol: '≤', kind: 'comparison' },
  { id: 'gt', label: 'Greater', symbol: '>', kind: 'comparison' },
  { id: 'ge', label: 'Greater or equal', symbol: '≥', kind: 'comparison' },
  { id: 'sum', label: 'Sum', symbol: 'Σ', kind: 'sum' }
];

export function operationKind(op: Operation): OperationKind {
  return OPERATIONS.find((o) => o.id === op)?.kind ?? 'arithmetic';
}

/** The type to decrypt a result as: `bool` for comparisons. */
export function resultType(op: Operation, type: IntegerType): ValueType {
  return operationKind(op) === 'comparison' ? 'bool' : type;
}

/**
 * The plaintext result the decrypted homomorphic result must equal: the same
 * semantics as the server (`heaas-core`'s `Operation::apply_plain`). `operands`
 * are in the type's range; binary operations take two (the scalar last).
 */
export function expectedResult(op: Operation, type: IntegerType, operands: bigint[]): PlainValue {
  if (op === 'sum') return wrap(type, operands.reduce((acc, v) => acc + v, 0n));
  const [a, b] = operands;
  switch (op) {
    case 'add':
      return wrap(type, a + b);
    case 'subtract':
      return wrap(type, a - b);
    case 'multiply':
      return wrap(type, a * b);
    case 'min':
      return a < b ? a : b;
    case 'max':
      return a > b ? a : b;
    case 'eq':
      return a === b;
    case 'ne':
      return a !== b;
    case 'lt':
      return a < b;
    case 'le':
      return a <= b;
    case 'gt':
      return a > b;
    case 'ge':
      return a >= b;
  }
}

/** A decrypted value as the worker reports it (`"true"`, `"-5"`), parsed. */
export function parsePlainValue(type: ValueType, text: string): PlainValue {
  return type === 'bool' ? text === 'true' : BigInt(text);
}
