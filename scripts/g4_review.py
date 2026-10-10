#!/usr/bin/env python3
"""VibeSec G4 LLM 審查紀錄工具：驗證 reviews/g4/<commit>.yaml，並把它與 CI 的靜態結果合成 G4 閘門狀態（docs/05、docs/09）。

子命令：
  check <record.yaml> [--head <sha>] [--no-git]       驗證紀錄（schema + 規則），並報告對 head 是否仍有效
  gate  --static reports/g4-gate.json --head <sha>    找出對 head 有效的紀錄，推導 G4 狀態並寫回 gate JSON 與 PR 留言
        [--out reports/g4-gate.json] [--comment reports/g4-comment.md] [--mode shadow|enforce]
  external-trust --base <sha> --head <sha> --pr-author <login> --reviews <reviews.json>
                                                      本 PR 新增／修改的 reviews/g4/external/*.yaml 不能自證：
                                                      recorded_by 須是在目前 head 上 approve 的非作者（CI 用）
  selftest                                            內建規則自我測試（validate.py 會呼叫）

紀錄來源：harness 寫 reports/g4-review.yaml（reports/ 不入版控），人工複製為 reviews/g4/<commit>.yaml 提交；
reviews/ 由 CODEOWNERS 審核。此工具不呼叫任何模型、不裁決、不改嚴重度／tier，只讀紀錄並推導狀態。

狀態推導（docs/05「阻擋政策」；incomplete ≠ pass，CLAUDE.md #2）：
  靜態 blocking，或 LLM 審查發現屬 blocking 且經人工裁決 confirm            → fail
  否則任一發現 requires_human 且沒有有效裁決（rulings/）                     → pending
  否則無紀錄／紀錄過期／family < min／必要角色缺席／coverage 有 pending、untested → incomplete
  否則                                                                         → pass
「有效」= 紀錄的 commit 是 head 的祖先，且兩者之間只動過 reviews/g4/ 與 rulings/。
退出碼：check 0 通過、1 違規；gate 0（shadow 或非 fail）、1（enforce 且 fail）；兩者 2 = 工具缺席（不放行）。
"""
from __future__ import annotations
import argparse, copy, datetime, json, os, pathlib, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
# 判定邏輯與設定（schema、vibesec.yaml、providers、catalogs、ruling.py）取自本腳本所在的樹；
# 受審資料（reviews/g4/、rulings/、git 歷史）取自 VIBESEC_PROJECT_ROOT。CI 以 base 分支的腳本跑 PR head 的資料，
# 讓 PR 不能改寫決定自己結果的程式（第四次 harness 審查 N3）。未設定時兩者相同（本機、harness）。
PROJECT = pathlib.Path(os.environ.get("VIBESEC_PROJECT_ROOT") or ROOT).resolve()
SCHEMA = ROOT / "schemas/g4-review.schema.json"
REVIEWS_DIR = PROJECT / "reviews/g4"
# 審查紀錄與其裁決之外的任何變更都讓紀錄過期（審的不是現在的程式碼）
FRESH_PREFIXES = ("reviews/g4/", "rulings/")
# Claude Code 內的 reviewer sub-agent（SKILL.md 步驟 2）不在 providers.yaml，但 family 固定
PROVIDER_ALIASES = {"claude-code-subagent": "anthropic"}
LLM_CONTROL = "VS-G4-LLM-REVIEW"
GRADE = {"E0": 0, "E1": 1, "E2": 2, "E3": 3}

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as e:  # incomplete ≠ pass
    print(f"工具缺席：{e.name}；無法驗證審查紀錄，視為未通過", file=sys.stderr)
    sys.exit(2)

sys.path.insert(0, str(ROOT / "scripts"))
import ruling as ruling_tool  # noqa: E402  人工裁決的規則（rulings/）與本工具共用同一份檢查


def _yaml(p: pathlib.Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_cfg() -> dict:
    vb = _yaml(ROOT / "vibesec.yaml")
    g4 = ((vb.get("gates") or {}).get("g4_access_control_review") or {})
    pv = (_yaml(ROOT / "config/providers.yaml").get("providers") or {})
    families = {name: (meta or {}).get("family") for name, meta in pv.items()}
    families.update(PROVIDER_ALIASES)
    return {"roles": list(g4.get("roles") or ["architecture", "identity-authz"]),
            "min_families": int((vb.get("review") or {}).get("min_families_for_high_risk", 2)),
            "provider_family": families}


def known_controls() -> set[str]:
    """config/catalogs/ 內出現的控制 ID（與 validate.py 同一個正則）。"""
    pat = re.compile(r"(ASVS5-V\d+\.\d+(\.\d+)?|LLM\d{2}:2025|MAESTRO-L[1-7]|VS-G[0-6]-[A-Z0-9-]+)")
    out: set[str] = set()
    for cat in ("cwe-map.yaml", "asvs-5.0-controls.yaml", "llm-top10-2025.yaml", "maestro-layers.yaml"):
        p = ROOT / "config/catalogs" / cat
        if p.exists():
            out |= {m.group(0) for m in pat.finditer(p.read_text(encoding="utf-8"))}
    return out


def _load_ruling(ref: str) -> dict | None:
    p = PROJECT / ref
    return _yaml(p) if p.is_file() else None


# ------------------------------------------------------------------ 規則
def evaluate(record: dict, cfg: dict, controls: set[str] | None = None, path: pathlib.Path | None = None,
             ruling_loader=_load_ruling) -> dict:
    """純邏輯（不碰 git）。回傳 {"errors": [...], "incomplete": [...], "findings": [有效狀態], "families": n}。
    errors = 紀錄本身自相矛盾或違規（不得採用）；incomplete = 誠實的缺口（紀錄可採用，但閘門不能 pass）。"""
    v = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")), format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = [f"schema：{e.message} @ {'/'.join(map(str, e.path)) or '(root)'}" for e in sorted(v.iter_errors(record), key=str)]
    if errors:
        return {"errors": errors, "incomplete": [], "findings": [], "families": 0}
    incomplete: list[str] = []
    # reviews/g4/<commit>.yaml（本 repo）與 reviews/g4/external/<commit>.yaml（外部專案）都以審查的 commit 命名
    if path is not None and path.parent.name in ("g4", "external") and path.stem != record["commit"]:
        errors.append(f"檔名 {path.name} 與 commit {record['commit']} 不一致（必須是 {path.parent.name}/<commit>.yaml）")

    # providers：名稱與 family 必須與 providers.yaml 一致（避免「兩個 family」是寫出來的）
    pf = cfg["provider_family"]
    ran: set[str] = set()
    for p in record["providers"]:
        fam = pf.get(p["provider"])
        if fam is None:
            errors.append(f"provider {p['provider']!r} 不在 config/providers.yaml（也不是 claude-code-subagent）")
        elif fam != p["family"]:
            errors.append(f"provider {p['provider']} 的 family 應為 {fam}，紀錄寫 {p['family']}")
        if p["state"] == "ran":
            ran.add(p["provider"])
    families = {p["family"] for p in record["providers"] if p["state"] == "ran"}
    if len(families) < cfg["min_families"]:
        incomplete.append(f"只有 {len(families)} 個 family 實際執行（需 ≥ {cfg['min_families']}）："
                          + "、".join(f"{p['provider']}={p['state']}" for p in record["providers"]))
    if not str(record["recorded_by"].get("handle") or "").strip():
        incomplete.append("recorded_by.handle 未填：紀錄尚未經人確認（harness 產出時留空，由複製提交的人填寫）")
    missing_roles = [r for r in cfg["roles"] if r not in record["roles"]]
    if missing_roles:
        incomplete.append("必要角色缺席：" + "、".join(missing_roles))

    cov = {c["control_id"]: c for c in record["coverage"]}
    if LLM_CONTROL not in cov:
        errors.append(f"coverage 缺 {LLM_CONTROL}")
    if controls:
        for cid in cov:
            if cid not in controls:
                errors.append(f"coverage control_id {cid} 不在 config/catalogs/")
    for cid, c in cov.items():
        if c["state"] in ("pending", "untested"):
            incomplete.append(f"coverage {cid}: {c['state']}" + (f"（{c['reason']}）" if c.get("reason") else ""))

    # findings：意見只能來自實際執行的 provider；分歧／少數意見／family 不足必須 requires_human；結論只能來自人工裁決
    effective = []
    for f in record["findings"]:
        fid = f["id"]
        for o in f["opinions"]:
            if o["provider"] not in ran:
                errors.append(f"{fid}: 意見來自未執行的 provider {o['provider']}")
            fam = pf.get(o["provider"])
            if fam is not None and fam != o["family"]:
                errors.append(f"{fid}: 意見的 provider {o['provider']} family 應為 {fam}")
        last = max(o["round"] for o in f["opinions"])
        final = [o for o in f["opinions"] if o["round"] == last]
        verdicts = {o["verdict"] for o in final}
        op_families = {o["family"] for o in f["opinions"]}
        divergent = len(verdicts) > 1 or "uncertain" in verdicts
        has_minority = any(o.get("minority") for o in f["opinions"])
        high_risk = f["policy_tier"] == "blocking"
        needs_human = divergent or has_minority or (high_risk and len(op_families) < cfg["min_families"])
        ruling = None
        if f.get("ruling_ref"):
            ruling = ruling_loader(f["ruling_ref"])
            if ruling is None:
                errors.append(f"{fid}: ruling_ref {f['ruling_ref']} 不存在")
            else:
                if ruling.get("finding_id") != fid:
                    errors.append(f"{fid}: {f['ruling_ref']} 的 finding_id 不是本發現")
                synthetic = {"id": fid, "review": {"requires_human": True, "opinions": f["opinions"]}}
                for e in ruling_tool.check(ruling, synthetic):
                    errors.append(f"{fid}: 裁決 {f['ruling_ref']} 違規：{e}")
        if ruling is None:
            if needs_human and not f["requires_human"]:
                errors.append(f"{fid}: 意見分歧／少數意見／family 不足，requires_human 必須為 true（不多數決）")
            if f["validation_status"] != "pending":
                errors.append(f"{fid}: 沒有人工裁決（ruling_ref）時 validation_status 只能是 pending；模型意見不是結論")
            if GRADE[f["evidence_grade"]] > 2:
                errors.append(f"{fid}: 只有模型意見時 evidence_grade 最高 E2（docs/09 §4）")
        # 有效狀態：裁決優先；否則照紀錄
        if ruling is not None and not any(s.startswith(f"{fid}: 裁決") for s in errors):
            dec = ruling["decision"]
            status = {"confirm": "confirmed", "refute": "refuted", "defer": "pending"}[dec]
            req_human = dec == "defer"
        else:
            status, req_human = f["validation_status"], f["requires_human"] or needs_human
        effective.append({"id": fid, "rule_id": f["rule_id"], "title": f["title"], "policy_tier": f["policy_tier"],
                          "validation_status": status, "requires_human": req_human, "ruling_ref": f.get("ruling_ref")})
    return {"errors": errors, "incomplete": incomplete, "findings": effective, "families": len(families)}


# ------------------------------------------------------------------ git
def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(PROJECT), *args], capture_output=True, text=True)


def freshness(commit: str, head: str) -> tuple[bool, str, int]:
    """(是否有效, 理由, 與 head 的距離)。有效 = commit 是 head 的祖先，且其後只動過 FRESH_PREFIXES。"""
    if _git("cat-file", "-e", f"{commit}^{{commit}}").returncode != 0:
        return False, f"commit {commit[:12]} 不在本地歷史（fetch-depth 不足或紀錄指向不存在的 commit）", 10**9
    if _git("merge-base", "--is-ancestor", commit, head).returncode != 0:
        return False, f"commit {commit[:12]} 不是 {head[:12]} 的祖先", 10**9
    diff = _git("diff", "--name-only", "--no-renames", commit, head)   # 改名搬進 rulings/ 也算變更（第四次審視 S-4）
    changed = [l for l in diff.stdout.splitlines() if l.strip() and not l.startswith(FRESH_PREFIXES)]
    dist = _git("rev-list", "--count", f"{commit}..{head}")
    n = int(dist.stdout.strip() or 0) if dist.returncode == 0 else 10**9
    if changed:
        shown = "、".join(changed[:5]) + ("…" if len(changed) > 5 else "")
        return False, f"commit {commit[:12]} 之後有程式變更（{len(changed)} 檔：{shown}），審查已過期", n
    return True, f"commit {commit[:12]} 之後只動過 reviews/g4/、rulings/", n


# ------------------------------------------------------------------ 閘門
def derive_gate(static: dict, record: dict | None, ev: dict | None, fresh_reason: str | None, record_ref: str | None) -> dict:
    """把靜態 gate JSON 與（有效的）審查紀錄合成 G4 gate JSON。record=None → 維持靜態結果 + LLM pending。"""
    gate = copy.deepcopy(static)
    static_blocking = int((static.get("findings_count") or {}).get("blocking") or 0)
    static_advisory = int((static.get("findings_count") or {}).get("advisory") or 0)
    coverage = [c for c in static.get("coverage") or [] if c.get("control_id") != LLM_CONTROL]
    tools = list(static.get("tools") or [])
    reasons: list[str] = []
    llm_blocking = llm_advisory = 0
    human_pending: list[str] = []
    if record is None or ev is None:
        reasons.append(fresh_reason or "G4 LLM 審查（VS-G4-LLM-REVIEW）未在 CI 執行，需由 /vibesec-harness 完成並提交 reviews/g4/<commit>.yaml")
        coverage.append({"control_id": LLM_CONTROL, "state": "pending", "reason": reasons[-1]})
        status = "fail" if static_blocking else "incomplete"
    else:
        for p in record["providers"]:
            # gate-result 的 tools 沒有 refused：資料分級不允許、未送出的 provider 記為 missing（未執行），exit_code 沿用 review_provider.py 的 3
            tools.append({"name": p["provider"], "version": p.get("model"),
                          "state": "missing" if p["state"] == "refused" else p["state"],
                          "exit_code": 3 if p["state"] == "refused" else None,
                          "output_ref": record_ref, "duration_seconds": None})
        coverage += [dict(c) for c in record["coverage"]]
        confirmed_blocking, unresolved_blocking = [], []
        for f in ev["findings"]:
            if f["validation_status"] == "refuted":
                continue
            if f["policy_tier"] == "blocking":
                llm_blocking += 1
                if f["validation_status"] == "confirmed":
                    confirmed_blocking.append(f["id"])
                elif not f["requires_human"]:
                    unresolved_blocking.append(f["id"])   # 模型一致 confirm 但無裁決：不能 pass（第四次審視 S-5）
            else:
                llm_advisory += 1
            if f["requires_human"]:
                human_pending.append(f["id"])
        if static_blocking or confirmed_blocking:
            status = "fail"
            if confirmed_blocking:
                reasons.append("LLM 審查發現經人工裁決 confirm 的 blocking：" + "、".join(confirmed_blocking))
        elif human_pending or unresolved_blocking:
            status = "pending"
            if human_pending:
                reasons.append("待人工裁決（rulings/）：" + "、".join(human_pending))
            if unresolved_blocking:
                reasons.append("blocking 發現尚未裁決（模型意見不能自行確認，docs/09 §5）：" + "、".join(unresolved_blocking))
        elif ev["incomplete"]:
            status = "incomplete"
            reasons.extend(ev["incomplete"])
        else:
            status = "pass"
        reasons.append(f"審查紀錄 {record_ref}（{ev['families']} family）")
        if ev["incomplete"] and status != "incomplete":
            reasons.extend(ev["incomplete"])
    gate.update({"status": status, "status_reason": "；".join(reasons) if reasons else None, "tools": tools,
                 "coverage": coverage,
                 "findings_count": {"blocking": static_blocking + llm_blocking, "advisory": static_advisory + llm_advisory},
                 "finished_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat()})
    gate["_llm_findings"] = ev["findings"] if ev else []   # 只給留言用；寫檔前移除
    return gate


def trust_cap(changed_in_pr: bool, handle: str, pr_author: str | None, approvers: list[str]) -> str | None:
    """紀錄能否把 G4 推到 pass。回傳 None = 可信；否則回傳理由（閘門最高 pending）。
    紀錄由本 PR 新增或修改時不能自證：recorded_by 不得是 PR 作者，且必須是在目前 head SHA 上 approve 的
    非作者之一——確認紀錄的人要親自核准，不能只填別人的帳號（比照 rulings/ 的職責分離，CLAUDE.md 規則 6；N6）。已在 base 分支上的紀錄經過另一個 PR 審查合併，視為可信。"""
    h = str(handle or "").lstrip("@").strip().lower()
    author = str(pr_author or "").lstrip("@").strip().lower()
    if not h:
        return "recorded_by.handle 未填，紀錄未經人確認"
    if not changed_in_pr:
        return None
    if author and h == author:
        return f"審查紀錄由本 PR 新增／修改，且 recorded_by 是 PR 作者 @{author}（不得自證）"
    others = sorted({x.lstrip("@").strip().lower() for x in approvers if x.strip()} - {author, ""})
    if not others:
        return "審查紀錄由本 PR 新增／修改，尚無非 PR 作者在目前 head 上 approve（approve 後再 push 需重新 approve）"
    if h not in others:
        return f"recorded_by @{h} 未在目前 head 上 approve（確認紀錄的人必須親自核准；目前核准者：{', '.join('@' + x for x in others)}）"
    return None


# 只採計有 repo 寫入關係者的核准：公開 repo 上任何帳號都能 approve（與 pr-gates.yml「取得目前 head 上的非作者 approve」相同）
TRUSTED_ASSOCIATIONS = {"OWNER", "MEMBER", "COLLABORATOR"}


def trusted_approvers(reviews: list[dict], pr_author: str, head_sha: str) -> list[str]:
    """GitHub pulls.listReviews 的結果 → 在 head_sha 上 approve、且不是 PR 作者的帳號（小寫）。
    每人只看最後一次非 COMMENTED／PENDING 的 review：之後的 CHANGES_REQUESTED、DISMISSED 會取消先前的 approve。"""
    last: dict[str, dict] = {}
    for r in reviews:
        login = ((r.get("user") or {}).get("login") or "").strip().lower()
        if not login or r.get("state") in ("COMMENTED", "PENDING"):
            continue
        last[login] = r
    author = str(pr_author or "").lstrip("@").strip().lower()
    return sorted(login for login, r in last.items()
                  if login != author and r.get("state") == "APPROVED" and r.get("commit_id") == head_sha
                  and r.get("author_association") in TRUSTED_ASSOCIATIONS)


def external_trust(records: dict[str, dict | None], pr_author: str, approvers: list[str],
                   cfg: dict, controls: set[str]) -> list[str]:
    """本 PR 新增／修改的外部紀錄 {路徑: 內容（無法解析為 None）} → 問題清單（空 = 全部可信）。"""
    problems = []
    for ref, rec in sorted(records.items()):
        if rec is None:
            problems.append(f"{ref}：無法解析"); continue
        ev = evaluate(rec, cfg, controls, pathlib.Path(ref))
        if ev["errors"]:
            problems.append(f"{ref}：違規：{ev['errors'][0]}"); continue
        cap = trust_cap(True, (rec.get("recorded_by") or {}).get("handle", ""), pr_author, approvers)
        if cap:
            problems.append(f"{ref}：{cap}")
    return problems


def apply_cap(gate: dict, reason: str) -> dict:
    """把 pass 降為 pending（fail／pending／incomplete 不變），並在理由與 coverage 註明。"""
    if gate["status"] == "pass":
        gate["status"] = "pending"
        gate["status_reason"] = "；".join(x for x in (f"審查紀錄未獲信任：{reason}", gate.get("status_reason")) if x)
        for c in gate.get("coverage") or []:
            if c.get("control_id") == LLM_CONTROL and c.get("state") == "pass":
                c.update(state="pending", reason=f"審查紀錄未獲信任：{reason}")
    elif reason:
        gate["status_reason"] = "；".join(x for x in (gate.get("status_reason"), f"審查紀錄未獲信任：{reason}") if x)
    return gate


def changed_since(base: str, head: str, path: str) -> bool:
    """path 在 base..head 之間有變更（本 PR 新增或修改）。git 失敗時視為有變更（fail closed）。"""
    r = _git("diff", "--name-only", f"{base}...{head}", "--", path)
    return r.returncode != 0 or bool(r.stdout.strip())


def record_changed(base: str | None, head: str, path: str) -> bool:
    """紀錄是否該視為「由本次變更引入」。沒有 base 可比對（workflow_dispatch、本機）→ True：
    分不出紀錄是不是作者自己剛加的，就不採信（fail closed；第四次審視 CI-3）。"""
    return (not base) or changed_since(base, head, path)


def comment_markdown(gate: dict, record_ref: str | None) -> str:
    st = gate["status"]
    lines = ["<!-- vibesec-g4-llm-review -->", "### VibeSec G4 — 存取控制", "",
             "G4 靜態檢查已完成（隱形 Unicode / RLS / Agent tool allow-list / HITL / 單層 middleware）。", "",
             f"**G4 狀態：`{st}`**——{gate.get('status_reason') or ''}"]
    if record_ref:
        rows = gate.get("_llm_findings") or []
        if rows:
            lines += ["", "| 發現 | 規則 | tier | 狀態 | 需人工裁決 |", "|---|---|---|---|---|"]
            lines += [f"| {f['id']} | `{f['rule_id']}` | {f['policy_tier']} | {f['validation_status']} | {'是' if f['requires_human'] else ''} |"
                      for f in rows]
        else:
            lines += ["", "LLM 審查未產生 G4 發現。"]
    else:
        lines += ["", "LLM 審查（VS-G4-LLM-REVIEW）尚未執行或已過期：執行 `/vibesec-harness`，把 `reports/g4-review.yaml` 複製為 "
                      "`reviews/g4/<commit>.yaml` 提交（格式：`schemas/g4-review.schema.json`；之後除 reviews/g4/、rulings/ 外不得再改程式碼）。"]
    lines += ["", "目前政策下 G4 `incomplete` / `pending` 不擋 merge；`fail` 只在 enforce 模式擋。"]
    return "\n".join(lines) + "\n"


def find_record(head: str, cfg: dict, controls: set[str]) -> tuple[dict | None, dict | None, str | None, str | None]:
    """對 head 有效、距離最近的紀錄。回傳 (record, evaluation, record_ref, 無紀錄時的理由)。"""
    best = None; notes: list[str] = []
    for p in sorted(REVIEWS_DIR.glob("*.yaml")):
        rel = str(p.relative_to(PROJECT))
        try:
            rec = _yaml(p)
        except yaml.YAMLError as e:
            notes.append(f"{rel} 無法解析（{type(e).__name__}）"); continue
        ev = evaluate(rec, cfg, controls, p)
        if ev["errors"]:
            notes.append(f"{rel} 違規：{ev['errors'][0]}"); continue
        ok, why, dist = freshness(rec["commit"], head)
        if not ok:
            notes.append(f"{rel}：{why}"); continue
        if best is None or dist < best[3]:
            best = (rec, ev, rel, dist)
    if best:
        return best[0], best[1], best[2], None
    reason = "G4 LLM 審查（VS-G4-LLM-REVIEW）未在 CI 執行，需由 /vibesec-harness 完成並提交 reviews/g4/<commit>.yaml"
    if notes:
        reason += "；既有紀錄不可用：" + "；".join(notes[:3])
    return None, None, None, reason


# ------------------------------------------------------------------ selftest
def _example() -> dict:
    return _yaml(ROOT / "docs/templates/g4-review.example.yaml")


def _example_ruling(fid: str) -> dict:
    r = _yaml(ROOT / "docs/templates/human-ruling.example.yaml")
    r["finding_id"] = fid
    r["minority_acknowledged"] = [{"role": "identity-authz", "provider": "openai-cloud", "response": "rejected", "comment": "gateway 未綁 owner"}]
    return r


def _static() -> dict:
    return {"gate": "G4", "status": "incomplete", "status_reason": "x", "mode": "shadow", "scope": "diff", "diff_base": None,
            "commit": None, "started_at": "2026-10-05T08:00:00+00:00", "finished_at": "2026-10-05T08:00:01+00:00",
            "tools": [{"name": "vibesec-g4-static", "version": "1.0.0", "state": "ran", "exit_code": 0, "output_ref": None, "duration_seconds": None}],
            "findings_count": {"blocking": 0, "advisory": 0},
            "coverage": [{"control_id": "VS-G4-RULES-FILE-UNICODE", "state": "pass", "reason": None},
                         {"control_id": LLM_CONTROL, "state": "pending", "reason": "x"}]}


def selftest() -> list[str]:
    fails: list[str] = []
    cfg = load_cfg(); controls = known_controls()
    gate_schema = Draft202012Validator(json.loads((ROOT / "schemas/gate-result.schema.json").read_text(encoding="utf-8")),
                                       format_checker=Draft202012Validator.FORMAT_CHECKER)

    def gate_of(rec, ev, fresh=True):
        g = derive_gate(_static(), rec, ev, None if fresh else "過期", "reviews/g4/x.yaml" if fresh else None) \
            if fresh else derive_gate(_static(), None, None, "紀錄過期", None)
        g.pop("_llm_findings", None)
        es = sorted(gate_schema.iter_errors(g), key=str)
        if es:
            fails.append(f"gate JSON 不符 schema：{es[0].message}")
        return g

    rec = _example()
    ev = evaluate(rec, cfg, controls, None)
    if ev["errors"]:
        fails.append(f"範例紀錄應通過：{ev['errors']}")
    if gate_of(rec, ev)["status"] != "pending":
        fails.append("範例（requires_human、無裁決）→ 閘門應為 pending")
    fid = rec["findings"][0]["id"]

    # 有效裁決 confirm → advisory 發現 confirmed，無 blocking → pass
    r2 = copy.deepcopy(rec); r2["findings"][0]["ruling_ref"] = f"rulings/{fid}.yaml"
    ev2 = evaluate(r2, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid))
    if ev2["errors"]:
        fails.append(f"附有效裁決應通過：{ev2['errors']}")
    elif (ev2["findings"][0]["validation_status"], ev2["findings"][0]["requires_human"]) != ("confirmed", False):
        fails.append("裁決 confirm 後有效狀態應為 confirmed / requires_human false")
    elif gate_of(r2, ev2)["status"] != "pass":
        fails.append("advisory 發現經裁決 confirm、無其他缺口 → 閘門應為 pass")
    # blocking + 裁決 confirm → fail
    r3 = copy.deepcopy(r2); r3["findings"][0]["policy_tier"] = "blocking"
    ev3 = evaluate(r3, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid))
    if ev3["errors"] or gate_of(r3, ev3)["status"] != "fail":
        fails.append("blocking 發現經裁決 confirm → 閘門應為 fail")
    # 無發現、兩 family、coverage pass → pass
    r4 = copy.deepcopy(rec); r4["findings"] = []; r4["coverage"] = [{"control_id": LLM_CONTROL, "state": "pass", "reason": None}]
    ev4 = evaluate(r4, cfg, controls, None)
    if ev4["errors"] or ev4["incomplete"] or gate_of(r4, ev4)["status"] != "pass":
        fails.append(f"無發現且 coverage pass → 閘門應為 pass（{ev4}）")
    # blocking 發現、模型一致 confirm、requires_human false、無裁決 → pending（不是 pass）
    r6 = copy.deepcopy(rec); f6 = r6["findings"][0]
    f6.update(policy_tier="blocking", requires_human=False, validation_status="pending", ruling_ref=None)
    for o in f6["opinions"]:
        o.update(verdict="confirm", minority=False)
    ev6 = evaluate(r6, cfg, controls, None)
    if ev6["errors"]:
        fails.append(f"一致 confirm 的 blocking 發現應能通過驗證：{ev6['errors']}")
    elif gate_of(r6, ev6)["status"] != "pending":
        fails.append("未裁決的 blocking 發現 → 閘門應為 pending，不是 pass")
    # 靜態 blocking 永遠 fail
    s = _static(); s["findings_count"]["blocking"] = 1
    if derive_gate(s, r4, ev4, None, "x")["status"] != "fail":
        fails.append("靜態 blocking → fail")
    # 無紀錄／過期 → incomplete
    if gate_of(None, None, fresh=False)["status"] != "incomplete":
        fails.append("無有效紀錄 → incomplete")

    def bad(label, mutate, expect, key="errors"):
        r = copy.deepcopy(rec); mutate(r)
        got = evaluate(r, cfg, controls, None)[key]
        if not any(expect in e for e in got):
            fails.append(f"應被擋下但沒有：{label}（{got}）")
    bad("family 與 providers.yaml 不符", lambda r: r["providers"][1].update(family="glm"), "family 應為")
    bad("未知 provider", lambda r: r["providers"][1].update(provider="mystery-llm"), "不在 config/providers.yaml")
    bad("意見來自未執行的 provider", lambda r: r["providers"][1].update(state="error"), "未執行的 provider")
    bad("分歧卻不交人工", lambda r: r["findings"][0].update(requires_human=False), "requires_human 必須為 true")
    bad("無裁決卻 confirmed", lambda r: r["findings"][0].update(validation_status="confirmed"), "只能是 pending")
    bad("只有模型意見卻 E3", lambda r: r["findings"][0].update(evidence_grade="E3"), "最高 E2")
    bad("缺 VS-G4-LLM-REVIEW", lambda r: r["coverage"][0].update(control_id="VS-G4-RULES-FILE-UNICODE"), "coverage 缺")
    bad("catalog 外的控制", lambda r: r["coverage"].append({"control_id": "ASVS5-V99.99", "state": "pass", "reason": None}), "不在 config/catalogs")
    bad("裁決指向別的發現", lambda r: r["findings"][0].update(ruling_ref="rulings/VS-20261003-1a2b3c4d.yaml"), "不存在")
    bad("只有一個 family", lambda r: r["providers"][1].update(state="timeout"), "個 family 實際執行", key="incomplete")
    bad("必要角色缺席", lambda r: r.update(roles=["architecture"]), "必要角色缺席", key="incomplete")
    # 一個 family 且無發現 → incomplete（不是 pass）
    r5 = copy.deepcopy(r4); r5["providers"][1]["state"] = "missing"
    ev5 = evaluate(r5, cfg, controls, None)
    if gate_of(r5, ev5)["status"] != "incomplete":
        fails.append("family < min → 閘門應為 incomplete")
    # 資料分級不允許而拒收（refused）照實記錄：紀錄通過 schema，不算 family，gate 的 tools 仍符合 gate-result schema
    r6 = copy.deepcopy(r4); r6["providers"][1]["state"] = "refused"
    ev6 = evaluate(r6, cfg, controls, None)
    g6 = gate_of(r6, ev6)
    if ev6["errors"] or g6["status"] != "incomplete" or not any("refused" in e for e in ev6["incomplete"]):
        fails.append(f"refused 的 provider 不算 family、紀錄仍有效（errors {ev6['errors']}、gate {g6['status']}）")
    if any(t["state"] == "refused" for t in g6["tools"]):
        fails.append("gate 的 tools 不得出現 refused（gate-result schema 沒有此值）")
    # 信任上限：本 PR 新增的紀錄不能自證
    if trust_cap(False, "appsec-lead", "author", []) is not None:
        fails.append("已在 base 上的紀錄（未在本 PR 變更）應可信")
    if trust_cap(True, "appsec-lead", "author", []) is None:
        fails.append("本 PR 新增的紀錄、無非作者 approve → 應不可信")
    if trust_cap(True, "appsec-lead", "author", ["author"]) is None:
        fails.append("只有 PR 作者自己 approve → 應不可信")
    if trust_cap(True, "@Author", "author", ["reviewer"]) is None:
        fails.append("recorded_by 是 PR 作者（大小寫、@ 不同）→ 應不可信")
    if trust_cap(True, "reviewer", "author", ["Reviewer"]) is not None:
        fails.append("recorded_by 是非作者核准者（大小寫不同）→ 應可信")
    if trust_cap(True, "appsec-lead", "author", ["reviewer"]) is None:
        fails.append("recorded_by 不是核准者（只填別人的帳號）→ 應不可信")
    if trust_cap(False, "", "author", ["reviewer"]) is None:
        fails.append("recorded_by.handle 空白 → 應不可信")
    if record_changed(None, "HEAD", "reviews/g4/x.yaml") is not True or record_changed("", "HEAD", "reviews/g4/x.yaml") is not True:
        fails.append("沒有 base 可比對 → 紀錄應視為本次變更引入（fail closed）")
    g4p = gate_of(r4, ev4)
    if apply_cap(g4p, "x")["status"] != "pending" or next(c for c in g4p["coverage"] if c["control_id"] == LLM_CONTROL)["state"] != "pending":
        fails.append("不可信的 pass → pending，且 VS-G4-LLM-REVIEW coverage 降為 pending")
    gf = derive_gate({**_static(), "findings_count": {"blocking": 1, "advisory": 0}}, r4, ev4, None, "x")
    gf.pop("_llm_findings", None)
    if apply_cap(gf, "x")["status"] != "fail":
        fails.append("上限不得把 fail 改掉")
    r6 = copy.deepcopy(r4); r6["recorded_by"]["handle"] = ""
    ev6 = evaluate(r6, cfg, controls, None)
    if ev6["errors"] or not any("handle 未填" in i for i in ev6["incomplete"]):
        fails.append("handle 空白：schema 應接受（harness 照 SKILL 留空），但列為缺口")
    if "pending" not in comment_markdown(gate_of(rec, ev), "x") or fid not in comment_markdown(gate_of(rec, ev), "x"):
        fails.append("留言應列出狀態與發現")
    # 核准者：與 pr-gates.yml 的 approve 擷取規則相同
    head = "a" * 40
    rv = lambda login, state, commit=head, assoc="COLLABORATOR": {"user": {"login": login}, "state": state,
                                                                    "commit_id": commit, "author_association": assoc}
    cases = [
        ([rv("Reviewer", "APPROVED")], ["reviewer"], "非作者在 head 上 approve → 採計（小寫）"),
        ([rv("author", "APPROVED")], [], "PR 作者自己 approve → 不採計"),
        ([rv("reviewer", "APPROVED", "b" * 40)], [], "approve 在舊 commit 上 → 不採計"),
        ([rv("reviewer", "APPROVED", assoc="NONE")], [], "沒有 repo 寫入關係 → 不採計"),
        ([rv("reviewer", "APPROVED"), rv("reviewer", "CHANGES_REQUESTED")], [], "approve 後 request changes → 取消"),
        ([rv("reviewer", "APPROVED"), rv("reviewer", "DISMISSED")], [], "approve 被 dismiss → 取消"),
        ([rv("reviewer", "APPROVED"), rv("reviewer", "COMMENTED")], ["reviewer"], "approve 後只留言 → 仍採計"),
    ]
    for reviews, want, why in cases:
        if trusted_approvers(reviews, "Author", head) != want:
            fails.append(f"trusted_approvers：{why}（得到 {trusted_approvers(reviews, 'Author', head)}）")
    ext = copy.deepcopy(r4); ext["recorded_by"]["handle"] = "reviewer"
    ref = f"reviews/g4/external/{ext['commit']}.yaml"
    if external_trust({ref: ext}, "author", ["reviewer"], cfg, controls):
        fails.append("外部紀錄：recorded_by 是在 head 上 approve 的非作者 → 應可信")
    if not external_trust({ref: ext}, "author", [], cfg, controls):
        fails.append("外部紀錄：沒有非作者 approve → 應不可信")
    ext_self = copy.deepcopy(ext); ext_self["recorded_by"]["handle"] = "author"
    if not external_trust({ref: ext_self}, "author", ["reviewer"], cfg, controls):
        fails.append("外部紀錄：recorded_by 是 PR 作者 → 應不可信")
    if not external_trust({f"reviews/g4/external/{'c' * 40}.yaml": ext}, "author", ["reviewer"], cfg, controls):
        fails.append("外部紀錄：檔名與 commit 不符 → 應違規")
    if not external_trust({ref: None}, "author", ["reviewer"], cfg, controls):
        fails.append("外部紀錄：無法解析 → 應不可信")
    return fails


# ------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("record"); c.add_argument("--head", default="HEAD"); c.add_argument("--no-git", action="store_true")
    g = sub.add_parser("gate"); g.add_argument("--static", required=True); g.add_argument("--head", required=True)
    g.add_argument("--out"); g.add_argument("--comment"); g.add_argument("--mode", default="shadow")
    g.add_argument("--base", help="PR base SHA；有值時檢查紀錄是否由本 PR 新增／修改")
    g.add_argument("--pr-author", default="")
    g.add_argument("--approvers", default="", help="在目前 head SHA 上 approve 的帳號，逗號分隔")
    x = sub.add_parser("external-trust")
    x.add_argument("--base", required=True); x.add_argument("--head", required=True)
    x.add_argument("--pr-author", required=True)
    x.add_argument("--reviews", required=True, help="GitHub pulls.listReviews 結果的 JSON 檔（無法取得時傳空檔 → 無核准者）")
    x.add_argument("--single-maintainer", action="store_true",
                   help="只有一位維護者、無法職責分離：問題改為警告（仍逐筆列出），不使 job 失敗")
    sub.add_parser("selftest")
    a = ap.parse_args(argv)
    cfg = load_cfg(); controls = known_controls()

    if a.cmd == "selftest":
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0

    if a.cmd == "check":
        p = pathlib.Path(a.record)
        ev = evaluate(_yaml(p), cfg, controls, p)
        for e in ev["errors"]: print(f"違規：{e}")
        for i in ev["incomplete"]: print(f"缺口：{i}（紀錄可採用，但閘門不能 pass）")
        if not a.no_git and not ev["errors"]:
            head = _git("rev-parse", a.head).stdout.strip()
            ok, why, _ = freshness(_yaml(p)["commit"], head)
            print(("有效：" if ok else "過期：") + why)
        print("check " + ("通過" if not ev["errors"] else "失敗"))
        return 1 if ev["errors"] else 0

    if a.cmd == "external-trust":
        r = _git("diff", "--name-only", "--diff-filter=AMR", f"{a.base}...{a.head}", "--", "reviews/g4/external/*.yaml")
        if r.returncode != 0:   # 無法判斷本 PR 動了哪些紀錄 → 不放行（fail closed）
            print(f"::error::無法取得 {a.base[:12]}...{a.head[:12]} 的變更清單：{r.stderr.strip()[-200:]}")
            return 1
        refs = [l.strip() for l in r.stdout.splitlines() if l.strip()]
        records: dict[str, dict | None] = {}
        for ref in refs:
            try:
                records[ref] = _yaml(PROJECT / ref)
            except Exception:
                records[ref] = None
        try:
            reviews = json.loads(pathlib.Path(a.reviews).read_text(encoding="utf-8") or "[]")
        except (OSError, json.JSONDecodeError):
            reviews = []   # 取不到 review → 沒有核准者 → 紀錄不可信（fail closed）
        approvers = trusted_approvers(reviews if isinstance(reviews, list) else [], a.pr_author, a.head)
        problems = external_trust(records, a.pr_author, approvers, cfg, controls)
        print(f"本 PR 新增／修改的外部 G4 紀錄 {len(refs)} 份；head {a.head[:12]} 上的非作者核准者：{', '.join(approvers) or '（無）'}")
        level = "warning" if a.single_maintainer else "error"
        for pb in problems:
            print(f"::{level}::{pb}" + ("（單一維護者，無法職責分離，僅警告）" if a.single_maintainer else ""))
        return 1 if problems and not a.single_maintainer else 0

    static = json.loads(pathlib.Path(a.static).read_text(encoding="utf-8"))
    head = _git("rev-parse", a.head).stdout.strip() or a.head
    record, ev, ref, reason = find_record(head, cfg, controls)
    gate = derive_gate(static, record, ev, reason, ref)
    if record is not None:
        changed = record_changed(a.base, head, ref)
        cap = trust_cap(changed, record["recorded_by"].get("handle", ""), a.pr_author,
                        [x for x in a.approvers.split(",") if x])
        if cap and not a.base:
            cap = "無 base 可比對（非 pull_request 事件），無法確認紀錄不是本次變更引入；" + cap
        if cap:
            apply_cap(gate, cap)
    md = comment_markdown(gate, ref)
    gate.pop("_llm_findings", None)
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.comment:
        pathlib.Path(a.comment).write_text(md, encoding="utf-8")
    print(f"G4 {gate['status']}：{gate.get('status_reason')}")
    if a.mode == "enforce" and gate["status"] == "fail":
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
