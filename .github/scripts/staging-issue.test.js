// node --test .github/scripts/staging-issue.test.js
const test = require('node:test');
const assert = require('node:assert/strict');
const { run, evaluate, MARKER } = require('./staging-issue.js');

function mockGithub(openIssues = []) {
  const calls = [];
  return {
    calls,
    rest: {
      issues: {
        listForRepo: 'listForRepo',
        create: async (a) => { calls.push(['create', a]); return { data: { number: 201 } }; },
        createComment: async (a) => { calls.push(['comment', a]); },
        update: async (a) => { calls.push(['update', a]); },
      },
    },
    paginate: async (fn, args) => { calls.push(['list', args]); return openIssues; },
  };
}
const context = { repo: { owner: 'o', repo: 'r' }, serverUrl: 'https://github.com', runId: 9, sha: 'abcdef1234567' };
const core = { info: () => {} };
const bb = (outputs, result = 'success') => ({ result, outputs });
const labOk = bb({ is_vulnapp: 'true', g5_status: 'fail', g5_blocking: '4', g6_status: 'fail', g6_blocking: '3' });
const extOk = bb({ is_vulnapp: 'false', g5_status: 'pass', g5_blocking: '0', g6_status: 'pass', g6_blocking: '0' });
const tracking = { number: 7, body: `${MARKER}\nold` };

test('lab: G5/G6 fail with blocking is the expected state → no problems', () => {
  assert.deepEqual(evaluate(labOk).problems, []);
});

test('lab: G5 pass or incomplete, or fail with 0 blocking, means detection regressed', () => {
  for (const [s, b] of [['pass', '0'], ['incomplete', '0'], ['fail', '0']]) {
    const e = evaluate(bb({ ...labOk.outputs, g5_status: s, g5_blocking: b }));
    assert.equal(e.problems.length, 1, `${s}/${b}`);
    assert.match(e.problems[0], /G5.*退步/);
  }
});

test('external target: fail or incomplete is a problem; pass is not', () => {
  assert.deepEqual(evaluate(extOk).problems, []);
  assert.equal(evaluate(bb({ ...extOk.outputs, g5_status: 'fail', g5_blocking: '2' })).problems.length, 1);
  assert.equal(evaluate(bb({ ...extOk.outputs, g6_status: 'incomplete' })).problems.length, 1);
});

test('missing gate result or failed/cancelled job is always a problem (incomplete ≠ pass)', () => {
  assert.equal(evaluate(bb({ ...labOk.outputs, g6_status: 'missing' })).problems.length, 1);
  assert.ok(evaluate(bb(labOk.outputs, 'failure')).problems.some((p) => /failure/.test(p)));
  assert.ok(evaluate(bb(labOk.outputs, 'cancelled')).problems.some((p) => /cancelled/.test(p)));
  assert.equal(evaluate(undefined).problems.length, 3);
});

test('problem with no open issue → opens one with marker and run link', async () => {
  const gh = mockGithub([]);
  const r = await run({ github: gh, context, core, blackbox: bb({ ...labOk.outputs, g5_status: 'incomplete' }) });
  assert.equal(r.action, 'opened');
  const [, args] = gh.calls.find((c) => c[0] === 'create');
  assert.ok(args.body.includes(MARKER));
  assert.ok(args.body.includes('https://github.com/o/r/actions/runs/9'));
  assert.ok(args.body.includes('靶場'));
  assert.equal(gh.calls.find((c) => c[0] === 'list')[1].creator, 'github-actions[bot]');
});

test('problem with open tracking issue → comments, no duplicate', async () => {
  const gh = mockGithub([tracking]);
  const r = await run({ github: gh, context, core, blackbox: bb(labOk.outputs, 'failure') });
  assert.deepEqual(r, { action: 'commented', issue: 7 });
  assert.equal(gh.calls.filter((c) => c[0] === 'create').length, 0);
});

test('nightly tracking issue (different marker) is not reused', async () => {
  const gh = mockGithub([{ number: 3, body: '<!-- vibesec-nightly-failure -->' }]);
  const r = await run({ github: gh, context, core, blackbox: bb(labOk.outputs, 'failure') });
  assert.equal(r.action, 'opened');
});

test('recovered with open issue → comment and close as completed; healthy with none → no writes', async () => {
  let gh = mockGithub([tracking]);
  assert.deepEqual(await run({ github: gh, context, core, blackbox: labOk }), { action: 'closed', issue: 7 });
  const [, upd] = gh.calls.find((c) => c[0] === 'update');
  assert.deepEqual([upd.state, upd.state_reason], ['closed', 'completed']);
  gh = mockGithub([]);
  assert.deepEqual(await run({ github: gh, context, core, blackbox: extOk }), { action: 'none' });
  assert.deepEqual(gh.calls.map((c) => c[0]), ['list']);
});
