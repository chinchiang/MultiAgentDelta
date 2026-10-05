// VibeSec nightly 失敗通知：由 nightly-full.yml 的 notify job 經 actions/github-script 呼叫。
//
// 行為：
//   - 任一 job 失敗或取消 → 找「未關閉、帶 MARKER 的追蹤 issue」：沒有就開一張；有就加一則留言（不重複開 issue）。
//   - 全部成功且有未關閉的追蹤 issue → 留言「已恢復」並關閉。
//   - 全部成功且沒有追蹤 issue → 什麼都不做。
// 輸入只來自本 workflow 的 job 結果與 evals.json（本 repo 的評測輸出），不讀任何外部使用者可控內容。
// 單元測試：.github/scripts/nightly-issue.test.js（node --test）。

const MARKER = '<!-- vibesec-nightly-failure -->';
const MAX_REGRESSIONS = 40;

const JOB_LABELS = {
  codeql: 'CodeQL 深度 SAST',
  'semgrep-full': 'Semgrep 全量',
  'g1-full': 'G1 全量供應鏈',
  evals: '評測（run_evals.py，對照 baseline）',
};

// needs：{ jobId: { result: 'success'|'failure'|'cancelled'|'skipped' } }
function failedJobs(needs) {
  return Object.entries(needs || {})
    .filter(([, v]) => v && (v.result === 'failure' || v.result === 'cancelled'))
    .map(([k, v]) => ({ id: k, result: v.result }));
}

function jobTable(needs) {
  const icon = { success: '✅', failure: '❌', cancelled: '⚠️', skipped: '⏭️' };
  const rows = Object.entries(needs || {}).map(
    ([k, v]) => `| ${JOB_LABELS[k] || k} | ${icon[v.result] || ''} \`${v.result}\` |`);
  return ['| Job | 結果 |', '|---|---|', ...rows].join('\n');
}

function regressionSection(evals, evalsJobFailed) {
  if (!evals) {
    // evals job 失敗卻沒有 evals.json → 評測根本沒跑完；這本身就要看 log，不能當成「沒有退步」
    return evalsJobFailed
      ? '### 評測\n\n沒有 `evals.json`：評測沒有跑完（安裝失敗、逾時或執行器錯誤）。請看 run log；這不代表沒有退步。'
      : '';
  }
  const regs = Array.isArray(evals.regressions) ? evals.regressions : [];
  const all = (evals.summary && evals.summary.ALL) || {};
  const head = `### 評測\n\n實測 ${all.executed ?? '?'} / ${all.total ?? '?'}，TP ${all.TP ?? '?'}、FP ${all.FP ?? '?'}、FN ${all.FN ?? '?'}、TN ${all.TN ?? '?'}`;
  if (!regs.length) return `${head}\n\n相對 baseline 沒有退步。`;
  const shown = regs.slice(0, MAX_REGRESSIONS).map((r) => `- ${r}`).join('\n');
  const more = regs.length > MAX_REGRESSIONS ? `\n- …另有 ${regs.length - MAX_REGRESSIONS} 項，見 artifact \`vibesec-nightly-evals\`` : '';
  return `${head}\n\n**相對 baseline 的退步（${regs.length}）**\n\n${shown}${more}`;
}

function failureBody({ needs, evals, runUrl, sha, date }) {
  const evalsFailed = failedJobs(needs).some((j) => j.id === 'evals');
  return [
    MARKER,
    `## VibeSec nightly 失敗（${date}）`,
    '',
    `Run：${runUrl}　commit：\`${(sha || '').slice(0, 7)}\``,
    '',
    jobTable(needs),
    '',
    regressionSection(evals, evalsFailed),
    '',
    '> 處理原則：先找根因。不得以 `continue-on-error`、縮減 `evals/baseline.yaml` 或放寬閘門讓它轉綠（CLAUDE.md 規則 1、2）；baseline 要縮減須由人類在獨立 PR 決定。',
    '> 此 issue 由 nightly 自動維護：之後再失敗會在這裡留言，恢復綠燈時自動關閉。',
  ].join('\n');
}

async function findOpenIssue(github, owner, repo) {
  const issues = await github.paginate(github.rest.issues.listForRepo, {
    owner, repo, state: 'open', creator: 'github-actions[bot]', per_page: 100,
  });
  return issues.find((i) => !i.pull_request && (i.body || '').includes(MARKER)) || null;
}

async function run({ github, context, core, needs, evals }) {
  const { owner, repo } = context.repo;
  const runUrl = `${context.serverUrl}/${owner}/${repo}/actions/runs/${context.runId}`;
  const date = new Date().toISOString().slice(0, 10);
  const failed = failedJobs(needs);
  const open = await findOpenIssue(github, owner, repo);

  if (failed.length) {
    const body = failureBody({ needs, evals, runUrl, sha: context.sha, date });
    if (open) {
      await github.rest.issues.createComment({ owner, repo, issue_number: open.number, body });
      core.info(`追加留言到 #${open.number}`);
      return { action: 'commented', issue: open.number };
    }
    const names = failed.map((j) => JOB_LABELS[j.id] || j.id).join('、');
    const created = await github.rest.issues.create({
      owner, repo, title: `VibeSec nightly 失敗：${names}`, body,
    });
    core.info(`開立 #${created.data.number}`);
    return { action: 'opened', issue: created.data.number };
  }

  if (open) {
    await github.rest.issues.createComment({
      owner, repo, issue_number: open.number,
      body: `${MARKER}\n✅ nightly 已恢復全綠（${date}）：${runUrl}\n\n自動關閉。`,
    });
    await github.rest.issues.update({ owner, repo, issue_number: open.number, state: 'closed', state_reason: 'completed' });
    core.info(`關閉 #${open.number}`);
    return { action: 'closed', issue: open.number };
  }
  return { action: 'none' };
}

module.exports = { run, failedJobs, failureBody, regressionSection, MARKER };
