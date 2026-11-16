import { describe, it, expect } from 'vitest';
import { judge } from './mutate-judge.mjs';

const report = (msgs) => JSON.stringify({ numFailedTests: msgs.length, testResults: [{ status: 'failed', message: '',
  assertionResults: [{ status: 'passed' }, ...msgs.map(m => ({ status: 'failed', failureMessages: [m] }))] }] });

describe('R8.6 a UI mutant red only through a crash is not red', () => {
  it('an assertion failure is red', () => {
    expect(judge(1, report(['AssertionError: expected 1 to be 2']))[0]).toBe('red');
  });
  it('a ReferenceError / not-a-function only is not landed', () => {
    expect(judge(1, report(['ReferenceError: cutNote is not defined']))[0]).toBe('NOT LANDED');
    expect(judge(1, report(['TypeError: fmt is not a function']))[0]).toBe('NOT LANDED');
  });
  it('one real assertion among crashes is red', () => {
    expect(judge(1, report(['ReferenceError: x is not defined', 'AssertionError: expected true']))[0]).toBe('red');
  });
  it('a TypeError that is behaviour (reading undefined) stays red', () => {
    expect(judge(1, report(["TypeError: Cannot read properties of undefined (reading 'x')"]))[0]).toBe('red');
  });
});
