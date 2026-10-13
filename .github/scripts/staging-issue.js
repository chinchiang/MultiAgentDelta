// VibeSec staging 黑箱通知：由 staging-blackbox.yml 的 notify job 經 actions/github-script 呼叫。
//
// 何時算「有問題」（evaluate）：判定不在這裡做。blackbox job 的 verdict 步驟以受信任的
// scripts/gate_verdict.py blackbox 算出問題清單（GLOSSARY.md「黑箱健康」：靶場看靶場驗收、外部目標看是否乾淨），
// 寫入 job output blackbox_problems（JSON 字串陣列，空陣列＝健康）；這裡照用，另加 job 失敗或取消。
// blackbox_problems 缺席、空字串或無法解析 → 有問題（incomplete ≠ pass）。
// 有問題 → 找「未關閉、帶 MARKER 的追蹤 issue」：沒有就開、有就留言；恢復 → 留言並關閉；一直正常 → 不寫入。
// 輸入只來自本 workflow 的 job 結果與輸出，不讀任何外部使用者可控內容。
// 單元測試：.github/scripts/staging-issue.test.js（node --test）。

const MARKER = '<!-- vibesec-staging-failure -->';

// blackbox：needs.blackbox，{ result, outputs: { is_vulnapp, blackbox_problems, g5_status, g5_blocking, g6_status, g6_blocking } }
// g5_*／g6_* 只供 job summary 顯示，不參與判定。
function evaluate(blackbox) {
  const problems = [];
  const result = blackbox && blackbox.result;
  const out = (blackbox && blackbox.outputs) || {};
  if (result !== 'success') problems.push(`blackbox job 結果為 \`${result || 'unknown'}\``);
  const lab = out.is_vulnapp === 'true';
  if (out.blackbox_problems === undefined || out.blackbox_problems === '') {
    // verdict 步驟沒有跑到或沒寫出結果：不知道黑箱閘門狀態，不能當成「沒有問題」
    problems.push('blackbox_problems 缺席（verdict 步驟未執行或未寫出 gate_verdict 的結果），無法確認黑箱閘門狀態');
    return { lab, problems };
  }
  let parsed;
  try { parsed = JSON.parse(out.blackbox_problems); } catch (e) { parsed = undefined; }
  if (!Array.isArray(parsed) || !parsed.every((p) => typeof p === 'string')) {
    // 無法判讀的判定結果不能當成「沒有問題」（incomplete ≠ pass）
    problems.push('blackbox_problems 無法解析（gate_verdict 的輸出格式不符），無法確認黑箱閘門狀態');
  } else {
    for (const p of parsed) if (!problems.includes(p)) problems.push(p);
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
