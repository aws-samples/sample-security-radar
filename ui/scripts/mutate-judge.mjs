// Pure verdict for one UI mutation (vitest exit code + JSON report). Split out of mutate.mjs, which runs the whole
// registry at import: a test importing judge() from it started a mutation run inside the test (R8.6, hung 10 min).
export const LOAD_ERROR = /SyntaxError|Transform failed|Failed to load|Cannot find module|failed to resolve import/i;

/**
 * Outcome from vitest's exit code + JSON report. Only a failing assertion counts as red; a suite that failed
 * to load/collect (0 assertion results, or a transform/syntax message) means the mutation broke the file.
 */
export const CRASH = /^(?:ReferenceError|SyntaxError)\b|^TypeError: .* is not (?:a function|a constructor|defined)\b/;

export function judge(status, reportText) {
  if (status === 0) return ['ALIVE?NO', 'test stayed green'];
  if (!reportText) return ['NOT LANDED', `vitest rc=${status} wrote no JSON report (crash before collection)`];
  let rep;
  try { rep = JSON.parse(reportText); } catch { return ['NOT LANDED', 'vitest JSON report unparsable'] ; }
  const broken = (rep.testResults ?? []).filter(t => t.status === 'failed' && ((t.assertionResults ?? []).length === 0 || LOAD_ERROR.test(t.message ?? '')));
  if (broken.length) return ['NOT LANDED', `mutation does not compile/load: ${String(broken[0].message ?? '').split('\n')[0].slice(0, 120)}`];
  // R8.6: failures that are all does-not-run crashes (a name the mutant removed, a call on something that no longer is a
  // function) are not an assertion catching the mutant — the guard would read as alive with no criterion behind it
  const failed = (rep.testResults ?? []).flatMap(t => (t.assertionResults ?? []).filter(a => a.status === 'failed'));
  const msgs = failed.flatMap(a => a.failureMessages ?? []);
  if (msgs.length && msgs.every(m => CRASH.test(m))) {
    return ['NOT LANDED', `red only through a crash: ${String(msgs[0]).split('\n')[0].slice(0, 120)}`];
  }
  if ((rep.numFailedTests ?? 0) > 0) return ['red', `${rep.numFailedTests} assertion(s) failed`];
  return ['NOT LANDED', `vitest rc=${status} but no failed assertion (runner error)`];
}
