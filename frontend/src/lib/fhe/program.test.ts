import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import type { IntegerType } from '../api.js';
import {
  checkProgram,
  evalProgram,
  formatProgram,
  inputNames,
  parseExpression,
  parseInputs,
  programResultType,
  programResultTypes
} from './program.js';

interface Vector {
  expr: string;
  type: IntegerType;
  inputs?: string[];
  result?: string;
  error?: string;
}

// The same cases heaas-core's expression tests run: both parsers must agree.
const vectors: Vector[] = JSON.parse(
  readFileSync(new URL('../../../../core/tests/program_vectors.json', import.meta.url), 'utf8')
);

describe('programs shared with the server', () => {
  it('has the shared vectors', () => {
    expect(vectors.length).toBeGreaterThan(20);
  });

  for (const v of vectors) {
    it(v.error ? `refuses ${JSON.stringify(v.expr)}` : `computes ${v.expr} on ${v.type}`, () => {
      const run = () => {
        const compiled = parseExpression(v.expr);
        const inputs = v.inputs ?? [];
        const checked = checkProgram(compiled.program, v.type, Math.max(compiled.inputCount, inputs.length));
        return evalProgram(checked, parseInputs(v.type, inputs) ?? []);
      };
      if (v.error) {
        expect(run).toThrow(v.error);
      } else {
        // Several results are written "r1, r2".
        expect(run().map(String).join(', ')).toBe(v.result);
      }
    });
  }
});

describe('programs', () => {
  it('compiles to the API’s step format', () => {
    const { program, inputCount } = parseExpression('3 < a ? b : a - b');
    expect(inputCount).toBe(2);
    expect(program.steps).toEqual([
      { op: 'gt', args: [{ input: 0 }, { const: '3' }] },
      { op: 'subtract', args: [{ input: 0 }, { input: 1 }] },
      { op: 'select', args: [{ step: 0 }, { input: 1 }, { step: 1 }] }
    ]);
    const checked = checkProgram(program, 'u8', 2);
    expect(programResultType(checked)).toBe('u8');
    expect(programResultType(checkProgram(parseExpression('a < b').program, 'u8', 2))).toBe('bool');
  });

  it('compiles lookups and several results', () => {
    const { program } = parseExpression('lookup(a, [2, 3], 9), a < b');
    expect(program).toEqual({
      steps: [
        {
          op: 'lookup',
          args: [{ input: 0 }, { const: '9' }],
          table: [
            { key: '0', value: '2' },
            { key: '1', value: '3' }
          ]
        },
        { op: 'lt', args: [{ input: 0 }, { input: 1 }] }
      ],
      outputs: [0, 1]
    });
    expect(programResultTypes(checkProgram(program, 'i8', 2))).toEqual(['i8', 'bool']);
    expect(formatProgram(program)).toBe('lookup(a, [0: 2, 1: 3], 9), a < b');
    expect(() => checkProgram({ ...program, outputs: [5] }, 'u8', 2)).toThrow('Output step 6');
    expect(() =>
      checkProgram({ steps: [{ op: 'add', args: [{ input: 0 }, { input: 0 }], table: [] }] }, 'u8', 1)
    ).toThrow('only lookup');
  });

  it('formats programs back into expressions that compute the same', () => {
    expect(formatProgram(parseExpression('(a + b) * 3 < c ? a : b').program)).toBe(
      '(((a + b) * 3) < c) ? a : b'
    );
    expect(formatProgram(parseExpression('min(a, -2) + rotl(b, 1)').program)).toBe(
      'min(a, -2) + rotl(b, 1)'
    );
    for (const v of vectors.filter((x) => x.result !== undefined)) {
      const original = parseExpression(v.expr);
      const inputs = parseInputs(v.type, v.inputs ?? []) ?? [];
      const count = Math.max(original.inputCount, inputs.length);
      const again = parseExpression(formatProgram(original.program));
      const result = evalProgram(checkProgram(again.program, v.type, count), inputs);
      expect(result.map(String).join(', '), `${v.expr} → ${formatProgram(original.program)}`).toBe(
        v.result
      );
    }
  });

  it('names inputs and refuses out-of-range values', () => {
    expect(inputNames(3)).toEqual(['a', 'b', 'c']);
    expect(parseInputs('u8', ['1', '255'])).toEqual([1n, 255n]);
    expect(parseInputs('u8', ['256'])).toBeNull();
  });

  it('refuses deep nesting without overflowing the stack', () => {
    expect(() => parseExpression(`${'('.repeat(100)}a${')'.repeat(100)}`)).toThrow('nests');
    expect(() => parseExpression('-'.repeat(200))).toThrow();
    expect(() => parseExpression('a'.repeat(5000))).toThrow('longer than');
  });
});
