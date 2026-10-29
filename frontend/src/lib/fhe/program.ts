/**
 * Programs (several operations in one job) and the expression syntax the
 * dashboard writes them in: the browser's copy of heaas-core's `program.rs` and
 * `expression.rs`. Both are tested against `core/tests/program_vectors.json`,
 * so they parse, type-check and evaluate expressions identically.
 */

import type { IntegerType, ValueType } from '../api.js';
import { parseValue, typeInfo, typeRange, wrap, type PlainValue } from './operations.js';

export type ProgramOp =
  | 'add'
  | 'subtract'
  | 'multiply'
  | 'divide'
  | 'remainder'
  | 'min'
  | 'max'
  | 'eq'
  | 'ne'
  | 'lt'
  | 'le'
  | 'gt'
  | 'ge'
  | 'and'
  | 'or'
  | 'xor'
  | 'not'
  | 'neg'
  | 'abs'
  | 'shl'
  | 'shr'
  | 'rotl'
  | 'rotr'
  | 'select';

/** A step argument as the API takes it. */
export type Arg = { input: number } | { step: number } | { const: string };

export interface Step {
  op: ProgramOp;
  args: Arg[];
}

export interface Program {
  steps: Step[];
}

/** heaas-core `MAX_PROGRAM_STEPS` and `MAX_INPUTS`. */
export const MAX_PROGRAM_STEPS = 64;
export const MAX_PROGRAM_INPUTS = 16;
const MAX_EXPRESSION_LEN = 4096;
const MAX_DEPTH = 64;
const INPUT_NAMES = 'abcdefghijklmnop';
const I128_MIN = -(1n << 127n);
const I128_MAX = (1n << 127n) - 1n;

type Kind = 'int' | 'bool';
type Operand = { ref: { input: number } | { step: number } } | { value: bigint };

export interface CheckedProgram {
  type: IntegerType;
  inputCount: number;
  steps: { op: ProgramOp; args: Operand[]; kind: Kind }[];
}

// ── Type check and plaintext evaluation ─────────────────────────────────────

const COMPARISONS = new Set<ProgramOp>(['eq', 'ne', 'lt', 'le', 'gt', 'ge']);

function constant(type: IntegerType, text: string): bigint {
  if (!/^\s*-?\d+\s*$/.test(text)) throw new Error(`"${text}" is not a whole number`);
  const value = BigInt(text.trim());
  const { min, max } = typeRange(type);
  if (value < min || value > max) {
    throw new Error(`${value} is outside the ${type} range (${min} to ${max})`);
  }
  return value;
}

function stepKind(op: ProgramOp, type: IntegerType, args: Operand[], kinds: (Kind | null)[]): Kind {
  const arity = op === 'not' || op === 'neg' || op === 'abs' ? 1 : op === 'select' ? 3 : 2;
  if (args.length !== arity) {
    throw new Error(`takes ${arity} argument${arity === 1 ? '' : 's'}, not ${args.length}`);
  }
  const first = kinds[0];
  if (first === null) throw new Error('the first argument must be encrypted, not a constant');
  switch (op) {
    case 'not':
      return first;
    case 'neg':
    case 'abs':
      if (first !== 'int') throw new Error('needs an integer');
      if (op === 'abs' && !typeInfo(type).signed) throw new Error(`needs a signed type, not ${type}`);
      return 'int';
    case 'select':
      if (first !== 'bool') throw new Error('the condition must be a boolean (a comparison)');
      if (kinds[1] === null || kinds[2] === null) {
        throw new Error('both branches must be encrypted, not constants');
      }
      if (kinds[1] !== 'int' || kinds[2] !== 'int') throw new Error('both branches must be integers');
      return 'int';
    case 'shl':
    case 'shr':
    case 'rotl':
    case 'rotr': {
      if (first !== 'int') throw new Error('needs an integer');
      const amount = args[1];
      if (!('value' in amount)) throw new Error('the shift amount must be a constant');
      const bits = BigInt(typeInfo(type).bits);
      if (amount.value < 0n || amount.value >= bits) {
        throw new Error(`shifts by 0 to ${bits - 1n} bits, not ${amount.value}`);
      }
      return 'int';
    }
  }
  if ((op === 'and' || op === 'or' || op === 'xor') && first === 'bool') {
    if (kinds[1] !== 'bool') throw new Error('on booleans, both arguments must be encrypted booleans');
    return 'bool';
  }
  if (first !== 'int' || kinds[1] === 'bool') throw new Error('needs integers, not booleans');
  const divisor = args[1];
  if ((op === 'divide' || op === 'remainder') && 'value' in divisor && divisor.value === 0n) {
    throw new Error('cannot divide by the constant 0');
  }
  return COMPARISONS.has(op) ? 'bool' : 'int';
}

/** Type-checks a program; throws an `Error` whose message names the step. */
export function checkProgram(program: Program, type: IntegerType, inputCount: number): CheckedProgram {
  if (program.steps.length === 0 || program.steps.length > MAX_PROGRAM_STEPS) {
    throw new Error(`A program has 1 to ${MAX_PROGRAM_STEPS} steps, not ${program.steps.length}`);
  }
  if (inputCount === 0 || inputCount > MAX_PROGRAM_INPUTS) {
    throw new Error(`A program takes 1 to ${MAX_PROGRAM_INPUTS} encrypted inputs, not ${inputCount}`);
  }
  const steps: CheckedProgram['steps'] = [];
  program.steps.forEach((step, index) => {
    try {
      const args: Operand[] = step.args.map((arg) => {
        if ('input' in arg) {
          if (arg.input < inputCount) return { ref: { input: arg.input } };
          throw new Error(`there is no input ${arg.input + 1} (the job has ${inputCount})`);
        }
        if ('step' in arg) {
          if (arg.step < index) return { ref: { step: arg.step } };
          throw new Error(`step ${arg.step + 1} is not an earlier step`);
        }
        return { value: constant(type, arg.const) };
      });
      const kinds = args.map((a): Kind | null =>
        'value' in a ? null : 'input' in a.ref ? 'int' : steps[a.ref.step].kind
      );
      steps.push({ op: step.op, args, kind: stepKind(step.op, type, args, kinds) });
    } catch (e) {
      throw new Error(`Step ${index + 1} (${step.op}): ${(e as Error).message}`);
    }
  });
  return { type, inputCount, steps };
}

export function programResultType(program: CheckedProgram): ValueType {
  return program.steps.at(-1)?.kind === 'bool' ? 'bool' : program.type;
}

/** One step on plaintexts, with exactly the encrypted semantics. */
function applyPlain(op: ProgramOp, type: IntegerType, args: PlainValue[]): PlainValue {
  const [x, y, z] = args;
  if (op === 'select') return x ? y : z;
  if (typeof x === 'boolean') {
    if (op === 'not') return !x;
    if (op === 'and') return x && (y as boolean);
    if (op === 'or') return x || (y as boolean);
    return x !== y; // xor
  }
  const a = x;
  const b = (y ?? 0n) as bigint;
  const { bits, signed } = typeInfo(type);
  const width = BigInt(bits);
  switch (op) {
    case 'add':
      return wrap(type, a + b);
    case 'subtract':
      return wrap(type, a - b);
    case 'multiply':
      return wrap(type, a * b);
    case 'divide':
    case 'remainder': {
      if (b === 0n) {
        if (op === 'remainder') return a;
        return !signed ? typeRange(type).max : a >= 0n ? -1n : 1n;
      }
      // BigInt division truncates toward zero, like TFHE-rs and Rust.
      return op === 'divide' ? wrap(type, a / b) : a % b;
    }
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
    case 'and':
      return wrap(type, a & b);
    case 'or':
      return wrap(type, a | b);
    case 'xor':
      return wrap(type, a ^ b);
    case 'not':
      return wrap(type, ~a);
    case 'neg':
      return wrap(type, -a);
    case 'abs':
      return wrap(type, a < 0n ? -a : a);
    case 'shl':
      return wrap(type, a << b);
    case 'shr':
      // Arithmetic for signed values, logical for unsigned ones (both are >> on
      // an in-range BigInt).
      return a >> b;
    case 'rotl':
    case 'rotr': {
      const u = BigInt.asUintN(bits, a);
      const n = op === 'rotl' ? b : (width - b) % width;
      const rotated = BigInt.asUintN(bits, (u << n) | (u >> ((width - n) % width)));
      return wrap(type, n === 0n ? u : rotated);
    }
  }
  throw new Error(`unknown operation ${op}`);
}

/** The plaintext result of a checked program on `inputs` (in the type's range). */
export function evalProgram(program: CheckedProgram, inputs: bigint[]): PlainValue {
  const values: PlainValue[] = [];
  for (const step of program.steps) {
    const args = step.args.map((a) =>
      'value' in a ? a.value : 'input' in a.ref ? inputs[a.ref.input] : values[a.ref.step]
    );
    values.push(applyPlain(step.op, program.type, args));
  }
  return values[values.length - 1];
}

// ── Expressions ─────────────────────────────────────────────────────────────

type Token = { pos: number } & ({ number: string } | { name: string } | { op: string });

const OPERATORS = [
  '<<', '>>', '<=', '>=', '==', '!=', '&&', '||',
  '+', '-', '*', '/', '%', '&', '|', '^', '!', '~', '<', '>', '?', ':', '(', ')', ','
];

function tokenize(text: string): Token[] {
  const tokens: Token[] = [];
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (/\s/.test(c)) {
      i++;
    } else if (/[0-9]/.test(c)) {
      const start = i;
      while (i < text.length && /[0-9]/.test(text[i])) i++;
      tokens.push({ pos: start, number: text.slice(start, i) });
    } else if (/[A-Za-z]/.test(c)) {
      const start = i;
      while (i < text.length && /[A-Za-z0-9_]/.test(text[i])) i++;
      tokens.push({ pos: start, name: text.slice(start, i) });
    } else {
      const op = OPERATORS.find((o) => text.startsWith(o, i));
      if (!op) throw new Error(`Unexpected '${c}' at position ${i + 1}`);
      tokens.push({ pos: i, op });
      i += op.length;
    }
  }
  return tokens;
}

type Expr =
  | { input: number }
  | { constant: bigint }
  | { neg: Expr }
  | { not: Expr }
  | { binary: string; left: Expr; right: Expr }
  | { ternary: [Expr, Expr, Expr] }
  | { call: string; args: Expr[] };

/** Binary operator levels, loosest first. */
const LEVELS = [
  ['||'],
  ['&&'],
  ['==', '!=', '<', '<=', '>', '>='],
  ['|'],
  ['^'],
  ['&'],
  ['<<', '>>'],
  ['+', '-'],
  ['*', '/', '%']
];

class Parser {
  pos = 0;
  depth = 0;
  constructor(
    readonly tokens: Token[],
    private textLength: number
  ) {}

  position(): number {
    return (this.tokens[this.pos]?.pos ?? this.textLength) + 1;
  }

  eat(op: string): boolean {
    const token = this.tokens[this.pos];
    if (token && 'op' in token && token.op === op) {
      this.pos++;
      return true;
    }
    return false;
  }

  expect(op: string) {
    if (!this.eat(op)) throw new Error(`Expected '${op}' at position ${this.position()}`);
  }

  nest() {
    if (++this.depth > MAX_DEPTH) {
      throw new Error(`The expression nests more than ${MAX_DEPTH} levels deep`);
    }
  }

  ternary(): Expr {
    this.nest();
    const condition = this.binary(0);
    let expr = condition;
    if (this.eat('?')) {
      const ifTrue = this.ternary();
      this.expect(':');
      const ifFalse = this.ternary();
      expr = { ternary: [condition, ifTrue, ifFalse] };
    }
    this.depth--;
    return expr;
  }

  binary(level: number): Expr {
    if (level === LEVELS.length) return this.unary();
    let left = this.binary(level + 1);
    let comparisons = 0;
    for (;;) {
      const token = this.tokens[this.pos];
      if (!token || !('op' in token) || !LEVELS[level].includes(token.op)) break;
      if (level === 2 && ++comparisons > 1) {
        throw new Error(
          `Comparisons cannot be chained (position ${this.position()}); use && between them`
        );
      }
      this.pos++;
      const right = this.binary(level + 1);
      left = { binary: token.op, left, right };
    }
    return left;
  }

  unary(): Expr {
    if (this.eat('-')) {
      this.nest();
      const operand = this.unary();
      this.depth--;
      return 'constant' in operand ? { constant: -operand.constant } : { neg: operand };
    }
    if (this.eat('!') || this.eat('~')) {
      this.nest();
      const operand = this.unary();
      this.depth--;
      return { not: operand };
    }
    return this.primary();
  }

  primary(): Expr {
    const position = this.position();
    const token = this.tokens[this.pos];
    if (!token) throw new Error('The expression ends too early');
    if ('number' in token) {
      this.pos++;
      const value = BigInt(token.number);
      if (value > (1n << 64n) - 1n) throw new Error(`The number at position ${position} is too large`);
      return { constant: value };
    }
    if ('name' in token) {
      this.pos++;
      if (this.eat('(')) {
        const args: Expr[] = [];
        if (!this.eat(')')) {
          for (;;) {
            args.push(this.ternary());
            if (this.eat(')')) break;
            this.expect(',');
          }
        }
        return { call: token.name, args };
      }
      const index = INPUT_NAMES.indexOf(token.name);
      if (token.name.length === 1 && index >= 0) return { input: index };
      throw new Error(
        `Unknown name '${token.name}' at position ${position}: inputs are the letters a to p`
      );
    }
    if (token.op === '(') {
      this.pos++;
      const expr = this.ternary();
      this.expect(')');
      return expr;
    }
    throw new Error(`Unexpected symbol at position ${position}`);
  }
}

const BINARY_OPS: Record<string, ProgramOp> = {
  '+': 'add',
  '-': 'subtract',
  '*': 'multiply',
  '/': 'divide',
  '%': 'remainder',
  '&': 'and',
  '&&': 'and',
  '|': 'or',
  '||': 'or',
  '^': 'xor',
  '<<': 'shl',
  '>>': 'shr',
  '==': 'eq',
  '!=': 'ne',
  '<': 'lt',
  '<=': 'le',
  '>': 'gt',
  '>=': 'ge',
  min: 'min',
  max: 'max'
};
const COMMUTATIVE = new Set<ProgramOp>(['add', 'multiply', 'and', 'or', 'xor', 'eq', 'ne', 'min', 'max']);
const FLIPPED: Partial<Record<ProgramOp, ProgramOp>> = { lt: 'gt', le: 'ge', gt: 'lt', ge: 'le' };

/** Evaluates an operation on two constants exactly (the range is checked later). */
function fold(op: string, programOp: ProgramOp, x: bigint, y: bigint): bigint {
  let value: bigint | null;
  switch (programOp) {
    case 'add':
      value = x + y;
      break;
    case 'subtract':
      value = x - y;
      break;
    case 'multiply':
      value = x * y;
      break;
    case 'divide':
    case 'remainder':
      if (y === 0n) throw new Error('cannot divide by the constant 0');
      value = programOp === 'divide' ? x / y : x % y;
      break;
    case 'and':
      value = x & y;
      break;
    case 'or':
      value = x | y;
      break;
    case 'xor':
      value = x ^ y;
      break;
    case 'shl':
      value = y >= 0n && y < 127n ? x << y : null;
      break;
    case 'shr':
      value = y >= 0n && y < 127n ? x >> y : null;
      break;
    case 'min':
      value = x < y ? x : y;
      break;
    case 'max':
      value = x > y ? x : y;
      break;
    default:
      throw new Error(`'${op}' needs at least one encrypted operand`);
  }
  if (value === null || value < I128_MIN || value > I128_MAX) {
    throw new Error(`The constant '${x} ${op} ${y}' is out of range`);
  }
  return value;
}

class Lowering {
  steps: Step[] = [];
  inputCount = 0;

  emit(op: ProgramOp, args: Arg[]): Arg {
    this.steps.push({ op, args });
    return { step: this.steps.length - 1 };
  }

  value(expr: Expr, what: string): Arg {
    const arg = this.lower(expr);
    if ('const' in arg) throw new Error(`${what} must be encrypted, not a constant`);
    return arg;
  }

  lower(expr: Expr): Arg {
    if ('input' in expr) {
      this.inputCount = Math.max(this.inputCount, expr.input + 1);
      return { input: expr.input };
    }
    if ('constant' in expr) return { const: String(expr.constant) };
    if ('neg' in expr) return this.emit('neg', [this.value(expr.neg, 'The operand of -')]);
    if ('not' in expr) return this.emit('not', [this.value(expr.not, 'The operand of !')]);
    if ('ternary' in expr) {
      const [c, t, f] = expr.ternary;
      const condition = this.value(c, 'The condition of ?:');
      const ifTrue = this.value(t, 'Both branches of ?:');
      const ifFalse = this.value(f, 'Both branches of ?:');
      return this.emit('select', [condition, ifTrue, ifFalse]);
    }
    if ('binary' in expr) {
      return this.binary(expr.binary, this.lower(expr.left), this.lower(expr.right));
    }
    const args = expr.args.map((a) => this.lower(a));
    const name = expr.call;
    if ((name === 'min' || name === 'max') && args.length === 2) return this.binary(name, args[0], args[1]);
    let op: ProgramOp;
    if (name === 'abs' && args.length === 1) op = 'abs';
    else if (name === 'rotl' && args.length === 2) op = 'rotl';
    else if (name === 'rotr' && args.length === 2) op = 'rotr';
    else if (['min', 'max', 'rotl', 'rotr'].includes(name)) {
      throw new Error(`${name}() takes 2 arguments, not ${args.length}`);
    } else if (name === 'abs') throw new Error(`abs() takes 1 argument, not ${args.length}`);
    else throw new Error(`Unknown function ${name}(): use min, max, abs, rotl or rotr`);
    if ('const' in args[0]) throw new Error(`The first argument of ${name}() must be encrypted`);
    return this.emit(op, args);
  }

  binary(op: string, a: Arg, b: Arg): Arg {
    const programOp = BINARY_OPS[op];
    if ('const' in a && 'const' in b) {
      return { const: String(fold(op, programOp, BigInt(a.const), BigInt(b.const))) };
    }
    if ('const' in a) {
      if (COMMUTATIVE.has(programOp)) return this.emit(programOp, [b, a]);
      const flipped = FLIPPED[programOp];
      if (flipped) return this.emit(flipped, [b, a]);
      if (programOp === 'subtract') return this.emit('add', [this.emit('neg', [b]), a]);
      throw new Error(`The left side of '${op}' must be encrypted, not a constant`);
    }
    return this.emit(programOp, [a, b]);
  }
}

export interface CompiledExpression {
  program: Program;
  /** One more than the highest input letter used. */
  inputCount: number;
}

/** Compiles an expression into a program (still to be checked for a type). */
export function parseExpression(text: string): CompiledExpression {
  if (text.length > MAX_EXPRESSION_LEN) {
    throw new Error(`The expression is longer than ${MAX_EXPRESSION_LEN} characters`);
  }
  const parser = new Parser(tokenize(text), text.length);
  const expr = parser.ternary();
  if (parser.pos !== parser.tokens.length) {
    throw new Error(`Unexpected symbol at position ${parser.position()}`);
  }
  const lowering = new Lowering();
  const result = lowering.lower(expr);
  if ('const' in result) throw new Error('The expression must use at least one input (a to p)');
  if ('input' in result) lowering.emit('add', [result, { const: '0' }]);
  return { program: { steps: lowering.steps }, inputCount: lowering.inputCount };
}

/** The input letters an expression reads: `["a", "b", "c"]`. */
export function inputNames(count: number): string[] {
  return INPUT_NAMES.slice(0, count).split('');
}

/** Parses the values typed for a program's inputs, in its type's range. */
export function parseInputs(type: IntegerType, texts: string[]): bigint[] | null {
  const values = texts.map((t) => parseValue(type, t));
  return values.every((v) => v !== null) ? (values as bigint[]) : null;
}

const SYMBOLS: Partial<Record<ProgramOp, string>> = {
  add: '+',
  subtract: '-',
  multiply: '*',
  divide: '/',
  remainder: '%',
  and: '&',
  or: '|',
  xor: '^',
  shl: '<<',
  shr: '>>',
  eq: '==',
  ne: '!=',
  lt: '<',
  le: '<=',
  gt: '>',
  ge: '>='
};

/**
 * A program as an expression (fully parenthesised inside), e.g. for the jobs
 * list. Parsing the text gives a program with the same results.
 */
export function formatProgram(program: Program): string {
  const texts: string[] = [];
  const arg = (a: Arg, nested: boolean) => {
    if ('input' in a) return INPUT_NAMES[a.input];
    if ('const' in a) return a.const.startsWith('-') && nested ? `(${a.const})` : a.const;
    const text = texts[a.step];
    const step = program.steps[a.step];
    const atomic = !(step.op in SYMBOLS) && step.op !== 'select' && step.op !== 'neg' && step.op !== 'not';
    return nested && !atomic ? `(${text})` : text;
  };
  for (const step of program.steps) {
    const [a, b, c] = step.args;
    const symbol = SYMBOLS[step.op];
    let text: string;
    if (symbol) text = `${arg(a, true)} ${symbol} ${arg(b, true)}`;
    else if (step.op === 'neg') text = `-${arg(a, true)}`;
    else if (step.op === 'not') text = `!${arg(a, true)}`;
    else if (step.op === 'select') text = `${arg(a, true)} ? ${arg(b, true)} : ${arg(c, true)}`;
    else text = `${step.op}(${step.args.map((x) => arg(x, false)).join(', ')})`;
    texts.push(text);
  }
  return texts.at(-1) ?? '';
}
