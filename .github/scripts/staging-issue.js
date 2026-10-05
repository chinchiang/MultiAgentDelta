// VibeSec staging 黑箱通知：由 staging-blackbox.yml 的 notify job 經 actions/github-script 呼叫。
//
// 何時算「有問題」（evaluate）：
//   - blackbox job 失敗或取消，或 G5 / G6 沒有產出閘門結果 → 有問題（incomplete ≠ pass）。
//   - 目標是靶場（examples/vulnapp，刻意有漏洞）：G5、G6 都「應該」是 fail 且 blocking > 0。
//     不是的話代表偵測能力退步（探針壞了、規則失效），要通知；fail 本身不通知。
//   - 目標是外部已授權環境（vars.VIBESEC_TARGET_URL）：G5 / G6 不是 pass（fail 或 incomplete）就通知。
// 有問題 → 找「未關閉、帶 MARKER 的追蹤 issue」：沒有就開、有就留言；恢復 → 留言並關閉；一直正常 → 不寫入。
// 輸入只來自本 workflow 的 job 結果與輸出，不讀任何外部使用者可控內容。
// 單元測試：.github/scripts/staging-issue.test.js（node --test）。

const MARKER = '<!-- vibesec-staging-failure -->';
const GATES = ['g5', 'g6'];

// blackbox：needs.blackbox，{ result, outputs: { is_vulnapp, g5_status, g5_blocking, g6_status, g6_blocking } }
function evaluate(blackbox) {
  const problems = [];
  const result = blackbox && blackbox.result;
  const out = (blackbox && blackbox.outputs) || {};
  if (result !== 'success') problems.push(`blackbox job 結果為 \`${result || 'unknown'}\``);
  const lab = out.is_vulnapp === 'true';
  for (const g of GATES) {
    const name = g.toUpperCase();
    const status = out[`${g}_status`] || '';
    const blocking = Number.parseInt(out[`${g}_blocking`] || '', 10);
    if (!status || status === 'missing') {
      problems.push(`${name} 沒有產出閘門結果（incomplete ≠ pass）`);
    } else if (lab) {
      if (status !== 'fail' || !(blocking > 0)) {
        problems.push(`${name} 在靶場上預期 \`fail\` 且有 blocking，實際為 \`${status}\`（blocking ${Number.isNaN(blocking) ? '?' : blocking}）：偵測能力可能退步`);
      }
    } else if (status !== 'pass') {
      problems.push(`${name} 為 \`${status}\`（blocking ${Number.isNaN(blocking) ? '?' : blocking}）`);
    }
  }
  return { lab, problems };
}

function body({ evaluation, runUrl, sha, date }) {
  const target = evaluation.lab ? '靶場 examples/vulnapp' : '外部已授權目標（vars.VIBESEC_TARGET_URL）';
  return [
    MARKER,
    `## VibeSec staging 黑箱需要處理（${date}）`,
    '',
    `Run：${runUrl}　commit：\`${(sha || '').slice(0, 7)}\`　目標：${target}`,
    '',
    ...evaluation.problems.map((p) => `- ${p}`),
    '',
    '> 處理原則：先找根因。不得以 `continue-on-error`、移除檢查或放寬閘門讓它轉綠（CLAUDE.md 規則 1、2）。',
    '> 此 issue 由 staging-blackbox 自動維護：之後再出問題會在這裡留言，恢復時自動關閉。',
  ].join('\n');
}

async function findOpenIssue(github, owner, repo) {
  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner, repo, state: 'open', creator: 'github-actions[bot]', per_page: 100,
  });
  return issues.find((i) => !i.pull_request && (i.body || '').includes(MARKER)) || null;
}

async function run({ github, context, core, blackbox }) {
  const { owner, repo } = context.repo;
  const runUrl = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  const date = new Date().toISOString().slice(0, 10);
  const evaluation = evaluate(blackbox);
  const open = await findOpenIssue(github, owner, repo);

  if (evaluation.problems.length) {
    const text = body({ evaluation, runUrl, sha: context.sha, date });
    if (open) {
      await github.rest.issues.createComment({ owner, repo, issue_number: open.number, body: text });
      core.info(`追加留言到 #${open.number}`);
      return { action: 'commented', issue: open.number };
    }
    const created = await github.rest.issues.create({
      owner, repo, title: `VibeSec staging 黑箱需要處理（${evaluation.problems.length} 項）`, body: text,
    });
    core.info(`開立 #${created.data.number}`);
    return { action: 'opened', issue: created.data.number };
  }
  if (open) {
    await github.rest.issues.createComment({
      owner, repo, issue_number: open.number,
      body: `${MARKER}\n✅ staging 黑箱已恢復預期狀態（${date}）：${runUrl}\n\n自動關閉。`,
    });
    await github.rest.issues.update({ owner, repo, issue_number: open.number, state: 'closed', state_reason: 'completed' });
    core.info(`關閉 #${open.number}`);
    return { action: 'closed', issue: open.number };
  }
  return { action: 'none' };
}

module.exports = { run, evaluate, MARKER };
