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
// 與 staging-blackbox.yml 的 job outputs 相同：blackbox_problems 由受信任的 scripts/gate_verdict.py blackbox 計算（空陣列＝健康）
const labOk = bb({ is_vulnapp: 'true', blackbox_problems: '[]', g5_status: 'fail', g5_blocking: '4', g6_status: 'fail', g6_blocking: '3' });
const extOk = bb({ is_vulnapp: 'false', blackbox_problems: '[]', g5_status: 'pass', g5_blocking: '0', g6_status: 'pass', g6_blocking: '0' });
const labRegressed = bb({ ...labOk.outputs, g5_status: 'incomplete', g5_blocking: '0',
  blackbox_problems: JSON.stringify(['G5 在靶場上預期 `fail` 且有 blocking，實際為 `incomplete`（blocking 0）：偵測能力可能退步']) });
const tracking = { number: 7, body: `${MARKER}\nold` };

test('problem with no open issue → opens one with marker and run link', async () => {
  const gh = mockGithub([]);
  const r = await run({ github: gh, context, core, blackbox: labRegressed });
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

// blackbox_problems：由受信任的 scripts/gate_verdict.py blackbox 計算；有就照用，不再由這裡判定
test('blackbox_problems present: empty list means healthy, regardless of legacy status fields', () => {
  const out = { is_vulnapp: 'true', blackbox_problems: '[]', g5_status: 'pass', g5_blocking: '0' };
  assert.deepEqual(evaluate(bb(out)).problems, []);
});

test('blackbox_problems present: problems are taken as-is and the lab flag is kept', () => {
  const ev = evaluate(bb({ is_vulnapp: 'true', blackbox_problems: JSON.stringify(['G6 必要工具未執行（garak）']) }));
  assert.equal(ev.lab, true);
  assert.deepEqual(ev.problems, ['G6 必要工具未執行（garak）']);
});

test('blackbox_problems present: a failed job is still a problem', () => {
  const ev = evaluate(bb({ is_vulnapp: 'false', blackbox_problems: '[]' }, 'failure'));
  assert.equal(ev.problems.length, 1);
  assert.match(ev.problems[0], /failure/);
});

test('blackbox_problems unparseable or not a string array → problem, never healthy (incomplete ≠ pass)', () => {
  for (const raw of ['{', '{"a":1}', '[1,2]', 'null']) {
    const ev = evaluate(bb({ is_vulnapp: 'false', blackbox_problems: raw }));
    assert.equal(ev.problems.length, 1, raw);
    assert.match(ev.problems[0], /無法解析/);
  }
});
