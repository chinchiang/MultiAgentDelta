// node --test .github/scripts/nightly-issue.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { run, failedJobs, regressionSection, MARKER } = require('./nightly-issue.js');

function mockGithub(openIssues = []) {
  const calls = [];
  const rest = {
    issues: {
      listForRepo: 'listForRepo',
      create: async (a) => { calls.push(['create', a]); return { data: { number: 101 } }; },
      createComment: async (a) => { calls.push(['comment', a]); },
      update: async (a) => { calls.push(['update', a]); },
    },
  };
  return {
    calls,
    rest,
    paginate: async (fn, args) => {
      calls.push(['list', args]);
      return openIssues;
    },
  };
}
const context = { repo: { owner: 'o', repo: 'r' }, serverUrl: 'https://github.com', runId: 7, sha: 'abcdef1234567' };
const core = { info: () => {} };
const ok = { codeql: { result: 'success' }, 'semgrep-full': { result: 'success' }, 'g1-full': { result: 'success' }, 'g1-attest': { result: 'success' }, 'g2-history': { result: 'success' }, evals: { result: 'success' } };
const evalsFailed = { ...ok, evals: { result: 'failure' } };
const evals = { summary: { ALL: { executed: 43, total: 73, TP: 22, FP: 0, FN: 1, TN: 20 } }, regressions: ['g2-secret-pos-01：FN（vibesec.g2.hardcoded-secret）'] };
const tracking = { number: 9, body: `${MARKER}\nold`, pull_request: undefined };

test('failedJobs: failure and cancelled count, skipped does not', () => {
  assert.deepEqual(failedJobs({ a: { result: 'failure' }, b: { result: 'cancelled' }, c: { result: 'skipped' }, d: { result: 'success' } }).map((j) => j.id), ['a', 'b']);
});

test('failure with no open issue → opens one with marker, run link and regressions', async () => {
  const gh = mockGithub([]);
  const r = await run({ github: gh, context, core, needs: evalsFailed, evals });
  assert.equal(r.action, 'opened');
  const [, args] = gh.calls.find((c) => c[0] === 'create');
  assert.match(args.title, /評測/);
  assert.ok(args.body.includes(MARKER));
  assert.ok(args.body.includes('https://github.com/o/r/actions/runs/7'));
  assert.ok(args.body.includes('g2-secret-pos-01'));
  assert.ok(args.body.includes('`abcdef1`'));
  assert.equal(gh.calls.filter((c) => c[0] === 'comment').length, 0);
  // 只找本 workflow 自己開的 issue
  assert.equal(gh.calls.find((c) => c[0] === 'list')[1].creator, 'github-actions[bot]');
});

test('failure with open tracking issue → comments, does not open a duplicate', async () => {
  const gh = mockGithub([tracking]);
  const r = await run({ github: gh, context, core, needs: evalsFailed, evals });
  assert.deepEqual(r, { action: 'commented', issue: 9 });
  assert.equal(gh.calls.filter((c) => c[0] === 'create').length, 0);
});

test('issues without the marker, or PRs, are not treated as the tracking issue', async () => {
  const gh = mockGithub([{ number: 3, body: 'unrelated' }, { number: 4, body: MARKER, pull_request: {} }]);
  const r = await run({ github: gh, context, core, needs: evalsFailed, evals });
  assert.equal(r.action, 'opened');
});

test('success with open tracking issue → comments recovery and closes as completed', async () => {
  const gh = mockGithub([tracking]);
  const r = await run({ github: gh, context, core, needs: ok, evals: { ...evals, regressions: [] } });
  assert.deepEqual(r, { action: 'closed', issue: 9 });
  const [, upd] = gh.calls.find((c) => c[0] === 'update');
  assert.deepEqual([upd.state, upd.state_reason], ['closed', 'completed']);
});

test('success with no tracking issue → no writes at all', async () => {
  const gh = mockGithub([]);
  const r = await run({ github: gh, context, core, needs: ok, evals });
  assert.equal(r.action, 'none');
  assert.deepEqual(gh.calls.map((c) => c[0]), ['list']);
});

test('evals job failed without evals.json → says evals did not finish, never "no regressions"', () => {
  const s = regressionSection(null, true);
  assert.match(s, /沒有跑完/);
  assert.doesNotMatch(s, /相對 baseline 沒有退步/);
});

test('cancelled run counts as failure (an interrupted nightly is not a pass)', async () => {
  const gh = mockGithub([]);
  const r = await run({ github: gh, context, core, needs: { ...ok, 'g1-full': { result: 'cancelled' } }, evals: null });
  assert.equal(r.action, 'opened');
});

test('long regression lists are truncated with a pointer to the artifact', () => {
  const many = { summary: { ALL: {} }, regressions: Array.from({ length: 55 }, (_, i) => `case-${i}`) };
  const s = regressionSection(many, true);
  assert.ok(s.includes('case-39'));
  assert.ok(!s.includes('case-40'));
  assert.match(s, /另有 15 項/);
});
