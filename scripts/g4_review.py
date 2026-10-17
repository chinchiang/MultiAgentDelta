#!/usr/bin/env python3
"""VibeSec G4 LLM 審查紀錄工具：驗證 reviews/g4/<commit>.yaml，並把它與 CI 的靜態結果合成 G4 閘門狀態（docs/05、docs/09）。

子命令：
  check <record.yaml> [--head <sha>] [--no-git]       驗證紀錄（schema + 規則），並報告對 head 是否仍有效
  gate  --static reports/g4-gate.json --head <sha>    找出對 head 有效的紀錄，推導 G4 狀態並寫回 gate JSON 與 PR 留言
        [--out reports/g4-gate.json] [--comment reports/g4-comment.md]
  external-trust --base <sha> --head <sha> --pr-author <login> --reviews <reviews.json>
                                                      本 PR 新增／修改的 reviews/g4/external/*.yaml 不能自證：
                                                      recorded_by 須是在目前 head 上 approve 的非作者（CI 用）
  selftest                                            內建規則自我測試（validate.py 會呼叫）

紀錄來源：harness 寫 reports/g4-review.yaml（reports/ 不入版控），人工複製為 reviews/g4/<commit>.yaml 提交；
reviews/ 由 CODEOWNERS 審核。此工具不呼叫任何模型、不裁決、不改嚴重度／tier，只讀紀錄並推導狀態。

狀態推導（docs/05「阻擋政策」；incomplete ≠ pass，CLAUDE.md #2）：
  靜態 blocking，或 LLM 審查發現屬 blocking 且經人工裁決 confirm            → fail
  否則任一發現 requires_human 且沒有有效裁決（rulings/）、有待裁決的 blocking 發現，
      或審查紀錄未獲信任（紀錄或裁決由本 PR 引入卻未經非作者 approve）                → pending
  （待裁決的 blocking 發現計入 findings_count：enforce 下阻擋判定依計數擋，直到人工裁決；GLOSSARY.md）
  否則無紀錄／紀錄過期／family < min／必要角色缺席／coverage 有 pending、untested → incomplete
  否則                                                                         → pass
「有效」= 紀錄的 commit 是 head 的祖先，且兩者之間只動過 reviews/g4/ 與 rulings/。
退出碼：check 0 通過、1 違規；gate 1（受信任政策的 mode 是 enforce，且閘門 fail 或有 blocking 計數——含待裁決的 blocking 發現，
與阻擋判定相同）、其餘 0；兩者 2 = 工具缺席（不放行）。
"""
from __future__ import annotations
import argparse, copy, json, os, pathlib, re, subprocess, sys

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
# sub-agent 的內容送到 Anthropic 雲端：資料分級比照 providers.yaml 的 anthropic-cloud（SKILL.md 步驟 4）
ALIAS_DATA_CLASSES = {"claude-code-subagent": ["public", "internal"]}
GRADE = {"E0": 0, "E1": 1, "E2": 2, "E3": 3}

try:
    import yaml
    from jsonschema import Draft202012Validator
except ImportError as e:  # incomplete ≠ pass
    print(f"工具缺席：{e.name}；無法驗證審查紀錄，視為未通過", file=sys.stderr)
    sys.exit(2)

sys.path.insert(0, str(ROOT / "scripts"))
import ruling as ruling_tool  # noqa: E402  人工裁決的規則（rulings/）與本工具共用同一份檢查
import gate_result  # noqa: E402  G4 組裝經 GateRun（#213）：外層欄位、tool 列、時間戳與判定只有一份寫法
from g4_static import LLM_CONTROL  # noqa: E402  LLM 審查控制 ID 的唯一來源（g4_static 不依賴 PyYAML）


def _yaml(p: pathlib.Path) -> dict:
    return yaml.safe_load(p.read_text(encoding="utf-8")) or {}


def load_cfg() -> dict:
    vb = _yaml(ROOT / "vibesec.yaml")
    g4 = ((vb.get("gates") or {}).get("g4_access_control_review") or {})
    pv = (_yaml(ROOT / "config/providers.yaml").get("providers") or {})
    families = {name: (meta or {}).get("family") for name, meta in pv.items()}
    families.update(PROVIDER_ALIASES)
    classes = {name: list((meta or {}).get("allowed_data_classes") or []) for name, meta in pv.items()}
    classes.update(ALIAS_DATA_CLASSES)
    review = vb.get("review") or {}
    return {"roles": list(g4.get("roles") or ["architecture", "identity-authz"]),
            "min_families": int(review.get("min_families_for_high_risk", 2)),
            "max_round": 1 + int(review.get("max_cross_rounds", 2)),
            "provider_family": families, "provider_classes": classes}


known_controls = gate_result.known_controls   # config/catalogs/ 內的控制 ID；讀取程式搬到 gate_result（#185）


def _load_ruling(ref: str) -> dict | None:
    p = PROJECT / ref
    return _yaml(p) if p.is_file() else None


# ------------------------------------------------------------------ 規則
def evaluate(record: dict, cfg: dict, controls: set[str] | None = None, path: pathlib.Path | None = None,
             ruling_loader=_load_ruling, policy_load: tuple | None = None) -> dict:
    """純邏輯（不碰 git）。回傳 {"errors": [...], "incomplete": [...], "findings": [有效狀態], "families": n}。
    errors = 紀錄本身自相矛盾或違規（不得採用）；incomplete = 誠實的缺口（紀錄可採用，但閘門不能 pass）。
    policy_load：vibesec_policy.load_policy 的結果；逐一評估多份紀錄的進入點建立一次傳入，沒給 → 這裡載入。"""
    v = Draft202012Validator(json.loads(SCHEMA.read_text(encoding="utf-8")), format_checker=Draft202012Validator.FORMAT_CHECKER)
    errors = [f"schema：{e.message} @ {'/'.join(map(str, e.path)) or '(root)'}" for e in sorted(v.iter_errors(record), key=str)]
    if errors:
        return {"errors": errors, "incomplete": [], "coverage_gaps": [], "findings": [], "families": 0}
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
            allowed = cfg["provider_classes"].get(p["provider"])
            if allowed is not None and record["data_class"] not in allowed:   # 規則 7：審查內容不得送到不收該分級的 provider
                errors.append(f"provider {p['provider']} 只收 {allowed}，卻收到 data_class={record['data_class']} 的審查內容（不得外傳）")
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
    coverage_gaps = []   # 結構化的 coverage 缺口（#213）：組裝依 state 決定經 coverage 還是未完成原因表達；incomplete 照舊列出（check 子指令）
    for cid, c in cov.items():
        if c["state"] in ("pending", "untested"):
            text = f"coverage {cid}: {c['state']}" + (f"（{c['reason']}）" if c.get("reason") else "")
            incomplete.append(text)
            coverage_gaps.append({"control_id": cid, "state": c["state"], "reason": c.get("reason"), "text": text})

    # findings：意見只能來自實際執行的 provider；分歧／少數意見／family 不足必須 requires_human；結論只能來自人工裁決
    effective = []
    # tier 只來自本工具樹（ROOT，受信任）的 blocking-policy.yaml＋risk_tier；紀錄（作者可寫）只能更嚴、不能降級
    from vibesec_policy import load_policy
    policy, problem = policy_load if policy_load is not None else load_policy(ROOT)
    if problem:   # 政策讀不到 → 記未完成原因、不產出任何發現（不以 blocking 照樣判定）→ 閘門 incomplete
        incomplete.append(problem)
    for f in record["findings"]:
        fid = f["id"]
        # 政策讀不到：紀錄的違規檢查照樣執行（external-trust 只看 errors），以較嚴的 blocking 驗證（requires_human 等）
        pol_tier = policy.tier(f["rule_id"]) if policy else "blocking"
        tier = "blocking" if "blocking" in (pol_tier, f["policy_tier"]) else "advisory"
        if policy and f["policy_tier"] != tier:
            incomplete.append(f"{fid}: 紀錄宣告 policy_tier={f['policy_tier']}，但 {f['rule_id']} 依阻擋政策（risk_tier "
                              f"{policy.risk_tier}）為 {tier}；以政策為準，紀錄不得降級（請修正紀錄）")
        for o in f["opinions"]:
            if o["provider"] not in ran:
                errors.append(f"{fid}: 意見來自未執行的 provider {o['provider']}")
            fam = pf.get(o["provider"])
            if fam is not None and fam != o["family"]:
                errors.append(f"{fid}: 意見的 provider {o['provider']} family 應為 {fam}")
        # 每個（角色, provider）取它自己最後一輪的意見：第 1 輪 refute、第 2 輪缺席（逾時）者，refute 仍算數；
        # 只看全域最後一輪會讓缺席者的少數意見消失（規則 6「保留少數意見、不多數決」）
        latest: dict[tuple[str, str], dict] = {}
        for o in f["opinions"]:
            k = (o["role"], o["provider"])
            if k not in latest or o["round"] >= latest[k]["round"]:
                latest[k] = o
            if o["round"] > cfg["max_round"]:
                errors.append(f"{fid}: 第 {o['round']} 輪超過上限（第 1 輪獨立 + 最多 {cfg['max_round'] - 1} 輪交叉，vibesec.yaml review.max_cross_rounds）")
        # 輪次結構（規則 6：第一輪獨立、之後最多兩輪交叉）：以前只檢查 round ≤ 上限，一份只有第 3 輪意見的紀錄也能通過，
        # 等於沒有獨立的第一輪。每個（角色, provider）都要有第 1 輪；第 N 輪（N ≥ 2）之前必須有第 N−1 輪（不能跳輪）；
        # 同一（角色, provider）同一輪只能有一筆（否則「自己最後一輪」不明確）
        by_key: dict[tuple[str, str], list[int]] = {}
        for o in f["opinions"]:
            by_key.setdefault((o["role"], o["provider"]), []).append(o["round"])
        for (role, prov), rounds in sorted(by_key.items()):
            if 1 not in rounds:
                errors.append(f"{fid}: {role}／{prov} 沒有第 1 輪獨立意見（第 {min(rounds)} 輪起才出現；規則 6：第一輪須獨立審查）")
            dup = sorted({r for r in rounds if rounds.count(r) > 1})
            if dup:
                errors.append(f"{fid}: {role}／{prov} 在第 {'、'.join(map(str, dup))} 輪有多筆意見（每輪只能一筆）")
        present = {o["round"] for o in f["opinions"]}
        for r in sorted(present):
            if r > 1 and r - 1 not in present:
                errors.append(f"{fid}: 有第 {r} 輪意見但沒有第 {r - 1} 輪（交叉輪須依序進行，不能跳輪）")
        verdicts = {o["verdict"] for o in latest.values()}
        op_families = {o["family"] for o in f["opinions"]}
        divergent = len(verdicts) > 1 or "uncertain" in verdicts
        has_minority = any(o.get("minority") for o in f["opinions"])
        high_risk = tier == "blocking"
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
        if policy:   # 政策讀不到 → 不分類：tier 只用來驗證，不產出發現
            effective.append({"id": fid, "rule_id": f["rule_id"], "title": f["title"], "policy_tier": tier,
                              "validation_status": status, "requires_human": req_human, "ruling_ref": f.get("ruling_ref")})
    return {"errors": errors, "incomplete": incomplete, "coverage_gaps": coverage_gaps, "findings": effective,
            "families": len(families)}


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
# coverage 合併時的嚴格程度（#213 決定 2）：同一個控制出現多次時取較嚴者
_STRICTNESS = {"fail": 4, "untested": 3, "pending": 2, "pass": 1, "not_applicable": 0}


def _merge_coverage(entries: list[dict]) -> list[dict]:
    """依出現順序合併同一控制的多筆 coverage：state 取較嚴者；理由是所有筆的理由依序串接、去重（較寬鬆那筆的理由也保留，
    讀者看得到每一個來源怎麼說）。schema 允許紀錄 coverage 與靜態檢查有同一個控制，或紀錄內重複；GateRun 每個控制只回報一次。"""
    states: dict[str, str] = {}
    reasons: dict[str, list[str]] = {}
    for c in entries:
        cid = c["control_id"]
        if cid not in states or _STRICTNESS[c["state"]] > _STRICTNESS[states[cid]]:
            states[cid] = c["state"]
        reasons.setdefault(cid, [])
        if c.get("reason") and c["reason"] not in reasons[cid]:
            reasons[cid].append(c["reason"])
    return [{"control_id": cid, "state": st, "reason": "；".join(reasons[cid]) or None} for cid, st in states.items()]


def derive_gate(static: dict, record: dict | None, ev: dict | None, fresh_reason: str | None, record_ref: str | None,
                trust_problems: list[str] | tuple[str, ...] = (), notes: list[str] | tuple[str, ...] = ()) -> tuple[dict, list[dict]]:
    """G4 組裝的唯一入口（#211、#213）：靜態結果＋（有效的）審查紀錄 → (G4 閘門結果, 審查發現)。
    record=None → 維持靜態結果、LLM 審查控制 pending。trust_problems：呼叫端算好的「審查紀錄未獲信任」理由（CI：紀錄或裁決
    由本 PR 引入卻未經非作者 approve；本機：外部紀錄的信任結果），當成待人工裁決交給閘門判定（以前由 apply_cap 在判定之外改寫）。
    狀態一律由 gate_verdict.verdict 判定（GateRun）；判定看的 coverage 就是輸出的 coverage。審查發現另外回傳（給 PR 留言用），
    不再塞在閘門結果的私有欄位裡。notes：呼叫端的附註（例如本機略過的 symlink），接在理由末尾、不影響狀態。
    外層欄位（mode、scope、diff_base、commit、risk_tier、started_at）取自 static；呼叫端要改寫時在 static 裡改好再傳入。"""
    trust_problems, extra_notes = list(trust_problems), list(notes)
    static_blocking = int((static.get("findings_count") or {}).get("blocking") or 0)
    static_advisory = int((static.get("findings_count") or {}).get("advisory") or 0)
    static_cov = [c for c in static.get("coverage") or [] if c.get("control_id") != LLM_CONTROL]
    tools = list(static.get("tools") or [])
    llm_advisory = 0
    confirmed_blocking: list[str] = []
    pending_ruling_blocking: list[str] = []   # 待裁決的 blocking 發現：blocking、未被 refute、尚無人工裁決
    problems: list[str] = []
    awaiting: list[str] = []
    notes: list[str] = []
    gaps: list[dict] = []
    if record is None or ev is None:
        problems.append(fresh_reason or "G4 LLM 審查（VS-G4-LLM-REVIEW）未在 CI 執行，需由 /vibesec-harness 完成並提交 reviews/g4/<commit>.yaml")
        record_cov = [{"control_id": LLM_CONTROL, "state": "pending", "reason": problems[-1]}]
    else:
        for p in record["providers"]:
            # gate-result 的 tools 沒有 refused：資料分級不允許、未送出的 provider 記為 missing（未執行），exit_code 沿用 review_provider.py 的 3
            tools.append(gate_result.tool(p["provider"], "missing" if p["state"] == "refused" else p["state"],
                                          version=p.get("model"), exit_code=3 if p["state"] == "refused" else None,
                                          output_ref=record_ref))
        record_cov = [dict(c) for c in record["coverage"]]
        human_pending = []
        for f in ev["findings"]:
            if f["validation_status"] == "refuted":
                continue
            if f["policy_tier"] == "blocking":
                if f["validation_status"] == "confirmed":
                    confirmed_blocking.append(f["id"])
                else:   # 模型一致 confirm 但無裁決（第四次審視 S-5），或交人工裁決中：都不能 pass，也不能自行 fail
                    pending_ruling_blocking.append(f["id"])
            else:
                llm_advisory += 1
            if f["requires_human"]:
                human_pending.append(f["id"])
        if confirmed_blocking:
            notes.append("LLM 審查發現經人工裁決 confirm 的 blocking：" + "、".join(confirmed_blocking))
        if human_pending:
            awaiting.append("rulings/：" + "、".join(human_pending))
        gaps = ev.get("coverage_gaps") or []
        notes.append(f"審查紀錄 {record_ref}（{ev['families']} family）")
    coverage = _merge_coverage(static_cov + record_cov)
    # 紀錄 coverage 的缺口：untested 由 coverage 表達（判定看得到），pending 是「待併入」、判定看不到 → 仍以未完成原因傳入
    # （#213 決定 1：否則紀錄 pending 會讓 G4 從 incomplete 變 pass）。合併後不是 untested 的（例如被靜態的 fail 蓋過）也照舊傳入
    untested_now = {c["control_id"] for c in coverage if c["state"] == "untested"}
    via_coverage = {g["text"] for g in gaps if g["state"] == "untested" and g["control_id"] in untested_now}
    if ev is not None and record is not None:
        problems.extend(p for p in ev["incomplete"] if p not in via_coverage)   # 紀錄本身的問題

    def build(cov: list[dict], trust: list[str]) -> gate_result.GateRun:
        run = gate_result.GateRun("G4", controls=[c["control_id"] for c in cov], mode=static.get("mode"),
                                  scope=static.get("scope"), commit=static.get("commit"), diff_base=static.get("diff_base"),
                                  risk_tier=static.get("risk_tier"), started_at=static.get("started_at"))
        for t in tools:
            run.tool(t["name"], t["state"], version=t.get("version"), exit_code=t.get("exit_code"), output_ref=t.get("output_ref"),
                     duration_seconds=t.get("duration_seconds"))
        for c in cov:
            run.cover(c["control_id"], c["state"], c["reason"])
        # 只有經人工裁決 confirm 的 LLM blocking 才讓閘門 fail；待裁決的 blocking 計入 findings_count、列為待人工裁決
        run.count(blocking=static_blocking + len(confirmed_blocking), advisory=static_advisory + llm_advisory)
        for p in problems:
            run.problem(p)
        for a in awaiting:
            run.awaiting_human(a)
        run.awaiting_blocking(pending_ruling_blocking)
        for t in trust:
            run.awaiting_human(f"審查紀錄未獲信任：{t}")
        for n in notes + extra_notes:
            run.note(n)
        return run

    # 信任問題：不算它們時本來會 pass，才把 LLM 審查控制的 coverage 降為 pending（#213 決定 3：維持 apply_cap 原本的行為）。
    # 判定規則只有 GateRun／verdict 一份：先不帶信任問題建一次看狀態。coverage 的理由只記第一則（apply_cap 逐則套用時只有
    # 第一次會改寫 coverage）；全部的信任問題都列在 status_reason
    if trust_problems and build(coverage, []).result()["status"] == "pass":
        coverage = [dict(c, state="pending", reason=f"審查紀錄未獲信任：{trust_problems[0]}")
                    if c["control_id"] == LLM_CONTROL and c["state"] == "pass" else c for c in coverage]
    return build(coverage, trust_problems).result(), (list(ev["findings"]) if ev else [])


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
                   cfg: dict, controls: set[str], policy_load: tuple | None = None) -> list[str]:
    """本 PR 新增／修改的外部紀錄 {路徑: 內容（無法解析為 None）} → 問題清單（空 = 全部可信）。
    policy_load：vibesec_policy.load_policy 的結果（沒給 → 這裡載入一次）；政策讀不到 → 無法判定，一律不可信（fail closed）。"""
    from vibesec_policy import load_policy
    policy_load = policy_load if policy_load is not None else load_policy(ROOT)
    problems = [f"{policy_load[1]}：無法判定外部紀錄是否可信"] if policy_load[1] and records else []
    for ref, rec in sorted(records.items()):
        if rec is None:
            problems.append(f"{ref}：無法解析"); continue
        ev = evaluate(rec, cfg, controls, pathlib.Path(ref), policy_load=policy_load)
        if ev["errors"]:
            problems.append(f"{ref}：違規：{ev['errors'][0]}"); continue
        cap = trust_cap(True, (rec.get("recorded_by") or {}).get("handle", ""), pr_author, approvers)
        if cap:
            problems.append(f"{ref}：{cap}")
    return problems


def ruling_caps(findings: list[dict], changed, pr_author: str | None, approvers: list[str], load) -> list[str]:
    """本 PR 新增或修改的人工裁決同樣不能自證：以前只檢查審查紀錄，PR 可以不動紀錄、只新增一份把發現翻成 refuted 的
    ruling（decided_by 隨便填別人的帳號），G4 就變 pass，而那個人根本不必 approve（第二輪審查 M4）。
    規則同 trust_cap：decided_by 必須是在目前 head 上 approve 的非作者。changed(path) 判斷是否由本 PR 引入。"""
    out = []
    for f in findings or []:
        ref = f.get("ruling_ref")
        if not ref or not changed(ref):
            continue
        r = load(ref) or {}
        c = trust_cap(True, str(((r.get("decided_by") or {}) if isinstance(r, dict) else {}).get("handle") or ""),
                      pr_author, approvers)
        if c:
            out.append(f"裁決 {ref}：" + c.replace("審查紀錄", "裁決").replace("recorded_by", "decided_by"))
    return out


def gate_exit_code(gate: dict, mode: str) -> int:
    """gate 子指令的退出碼，與阻擋判定（gate_verdict enforce）的規則相同（#214）：enforce 下閘門 fail，或 findings_count 有
    blocking（含待裁決的 blocking 發現，GLOSSARY.md）→ 1；其餘 0。以前只看 fail：待裁決的 blocking 在這一步 exit 0、到 summary 才擋。"""
    blocking = int((gate.get("findings_count") or {}).get("blocking") or 0)
    return 1 if mode == "enforce" and (gate.get("status") == "fail" or blocking > 0) else 0


def changed_since(base: str, head: str, path: str) -> bool:
    """path 在 base..head 之間有變更（本 PR 新增或修改）。git 失敗時視為有變更（fail closed）。"""
    r = _git("diff", "--name-only", f"{base}...{head}", "--", path)
    return r.returncode != 0 or bool(r.stdout.strip())


def record_changed(base: str | None, head: str, path: str) -> bool:
    """紀錄是否該視為「由本次變更引入」。沒有 base 可比對（workflow_dispatch、本機）→ True：
    分不出紀錄是不是作者自己剛加的，就不採信（fail closed；第四次審視 CI-3）。"""
    return (not base) or changed_since(base, head, path)


_MD_SPECIAL = re.compile(r"([\\`*_\[\]()<>!|#~])")


def md_safe(text) -> str:
    """留言由 bot 身分發出：status_reason 會帶入審查紀錄的 coverage reason、檔名等受測方可控的字串，
    跳脫 Markdown／HTML 控制字元並把 @ 換成全形，避免以 bot 名義插入連結、圖片或 @mention（第二輪審查 L4）。"""
    t = str(text or "").replace("\r", " ").replace("\n", " ")
    return _MD_SPECIAL.sub(r"\\\1", t).replace("@", "＠")


def comment_markdown(gate: dict, record_ref: str | None, llm_findings=()) -> str:
    st = gate["status"]
    lines = ["<!-- vibesec-g4-llm-review -->", "### VibeSec G4 — 存取控制", "",
             "G4 靜態檢查已完成（隱形 Unicode / RLS / Agent tool allow-list / HITL / 單層 middleware / MCP resource indicator）。", "",
             f"**G4 狀態：`{md_safe(st)}`**——{md_safe(gate.get('status_reason'))}"]
    if record_ref:
        rows = list(llm_findings)
        if rows:
            lines += ["", "| 發現 | 規則 | tier | 狀態 | 需人工裁決 |", "|---|---|---|---|---|"]
            lines += [f"| {md_safe(f['id'])} | {md_safe(f['rule_id'])} | {md_safe(f['policy_tier'])} | {md_safe(f['validation_status'])} | {'是' if f['requires_human'] else ''} |"
                      for f in rows]
        else:
            lines += ["", "LLM 審查未產生 G4 發現。"]
    else:
        lines += ["", "LLM 審查（VS-G4-LLM-REVIEW）尚未執行或已過期：執行 `/vibesec-harness`，把 `reports/g4-review.yaml` 複製為 "
                      "`reviews/g4/<commit>.yaml` 提交（格式：`schemas/g4-review.schema.json`；之後除 reviews/g4/、rulings/ 外不得再改程式碼）。"]
    lines += ["", "目前政策下 G4 `incomplete` / `pending` 不擋 merge；`fail` 只在 enforce 模式擋。"]
    return "\n".join(lines) + "\n"


def find_record(head: str, cfg: dict, controls: set[str],
                policy_load: tuple | None = None) -> tuple[dict | None, dict | None, str | None, str | None]:
    """對 head 有效、距離最近的紀錄。回傳 (record, evaluation, record_ref, 無紀錄時的理由)。
    policy_load：vibesec_policy.load_policy 的結果（沒給 → 這裡載入一次，所有紀錄共用）。"""
    from vibesec_policy import load_policy
    policy_load = policy_load if policy_load is not None else load_policy(ROOT)
    best = None; notes: list[str] = []
    for p in sorted(REVIEWS_DIR.glob("*.yaml")):
        rel = str(p.relative_to(PROJECT))
        try:
            rec = _yaml(p)
        except yaml.YAMLError as e:
            notes.append(f"{rel} 無法解析（{type(e).__name__}）"); continue
        ev = evaluate(rec, cfg, controls, p, policy_load=policy_load)
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

    def gate_of(rec, ev, fresh=True, trust_problems=()):
        g, _ = derive_gate(_static(), rec, ev, None if fresh else "過期", "reviews/g4/x.yaml" if fresh else None,
                           trust_problems=trust_problems) \
            if fresh else derive_gate(_static(), None, None, "紀錄過期", None)
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

    # 有效裁決 confirm → advisory 發現 confirmed，無 blocking → pass（規則須在政策上也是 advisory）
    r2 = copy.deepcopy(rec); r2["findings"][0].update(ruling_ref=f"rulings/{fid}.yaml", policy_tier="advisory",
                                                      rule_id="vibesec.g4.single-middleware-authz")
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
    # 紀錄不能把政策 blocking 的規則降為 advisory（schema 只收 vibesec.g4.*；本 repo L3 下 missing-owner-filter 等由
    # tier_overrides 升為 blocking）。政策下沒有任何 G4 blocking 規則時，以 risk_tier L3 的同一份政策檔驗證
    import vibesec_policy
    pol = vibesec_policy.Policy(ROOT)
    if not any(r.startswith("vibesec.g4.") for r in pol.effective_blocking()):
        pol = vibesec_policy.Policy(ROOT, risk_tier="L3")
    g4_blocking = sorted(r for r in pol.effective_blocking() if r.startswith("vibesec.g4."))
    if not g4_blocking:
        fails.append("政策（含 L3 tier_overrides）沒有任何 vibesec.g4.* blocking 規則，無法驗證紀錄降級")
    saved_policy = vibesec_policy.Policy
    vibesec_policy.Policy = lambda *a, **k: pol
    try:
        for rid in g4_blocking:
            rd = copy.deepcopy(r2); rd["findings"][0].update(rule_id=rid, policy_tier="advisory")
            evd = evaluate(rd, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid))
            gd = gate_of(rd, evd)
            if evd["errors"] or evd["findings"][0]["policy_tier"] != "blocking" or gd["status"] != "fail" \
                    or gd["findings_count"]["blocking"] < 1:
                fails.append(f"紀錄把政策 blocking 的 {rid} 寫成 advisory、裁決 confirm → 應以 blocking 計且閘門 fail（{gd['status']}）")
            if not any("不得降級" in e for e in evd["incomplete"]):
                fails.append(f"{rid}：紀錄 tier 低於政策應記入 incomplete")
            # 高風險（政策 blocking）即使紀錄寫 advisory，family 不足也必須交人工
            rh = copy.deepcopy(rec); fh = rh["findings"][0]
            fh.update(rule_id=rid, policy_tier="advisory", requires_human=False, ruling_ref=None)
            fh["opinions"] = [dict(o, verdict="confirm", minority=False) for o in fh["opinions"] if o["family"] == fh["opinions"][0]["family"]]
            if not any("requires_human 必須為 true" in e for e in evaluate(rh, cfg, controls, None)["errors"]):
                fails.append(f"{rid}：政策 blocking、只有一個 family 的意見 → requires_human 必須為 true（紀錄寫 advisory 不能跳過）")
    finally:
        vibesec_policy.Policy = saved_policy

    # 紀錄比政策嚴（advisory 規則宣告 blocking）→ 採較嚴者、不記 incomplete
    rs = copy.deepcopy(r2); rs["findings"][0]["policy_tier"] = "blocking"
    evs = evaluate(rs, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid))
    if evs["findings"][0]["policy_tier"] != "blocking" or any("不得降級" in e for e in evs["incomplete"]):
        fails.append("紀錄宣告比政策嚴的 tier → 應採 blocking、不記降級")
    # 政策載入失敗 → 不分類任何發現、記未完成原因、閘門 incomplete（以前 LLM 發現一律以 blocking 照樣判定：
    # 經裁決 confirm 就報 fail，原因寫錯）。紀錄本身的違規檢查照樣執行：external-trust 只看 errors，
    # 跳過檢查會讓違規的紀錄被判為可信
    with vibesec_policy.broken_policy_root() as bpr:
        broken = vibesec_policy.load_policy(bpr)
    evb = evaluate(r2, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid), policy_load=broken)
    if evb["findings"] or evb["errors"] or not any(e.startswith(vibesec_policy.POLICY_UNREADABLE + "（") for e in evb["incomplete"]) \
            or gate_of(r2, evb)["status"] != "incomplete":
        fails.append(f"阻擋政策無法載入 → 不分類 LLM 發現、記 incomplete、閘門 incomplete（得到 {evb}）")
    rbad = copy.deepcopy(r2); rbad["findings"][0]["opinions"][0]["provider"] = "ghost-provider"
    evbad = evaluate(rbad, cfg, controls, None, ruling_loader=lambda ref: _example_ruling(fid), policy_load=broken)
    if not any("未執行的 provider" in e for e in evbad["errors"]) or evbad["findings"]:
        fails.append(f"阻擋政策無法載入 → 紀錄的違規檢查照樣執行（意見來自未執行的 provider 應記入 errors；得到 {evbad['errors']}）")
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
    if derive_gate(s, r4, ev4, None, "x")[0]["status"] != "fail":
        fails.append("靜態 blocking → fail")
    # 重現：審查紀錄有效時，靜態結果 coverage 的 untested（READ_ERR、MCP 檢查無法執行）不得被忽略而報 pass
    for cid, why in (("VS-G4-AGENT-TOOL-ALLOWLIST", "無法讀取：app.py（PermissionError）"),
                     ("VS-G4-MCP-RESOURCE-INDICATOR", "MCP resource indicator 檢查無法執行")):
        s = _static(); s["coverage"].append({"control_id": cid, "state": "untested", "reason": why})
        g, _ = derive_gate(s, r4, ev4, None, "x")
        if g["status"] == "pass" or why not in (g["status_reason"] or ""):
            fails.append(f"有效審查紀錄 + 靜態 {cid} untested → 不得為 pass，並寫明原因（得到 {g['status']}：{g['status_reason']}）")
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

    def minority_vanishes(r):   # 第 1 輪 refute 的 provider 在之後的輪次缺席（逾時），另一方第 3 輪 confirm
        f = r["findings"][0]
        f["opinions"] = [o for o in f["opinions"] if not (o["provider"] == "openai-cloud" and o["round"] == 3)]
        for o in f["opinions"]:
            o["minority"] = False
        f["requires_human"] = False
    bad("第 1 輪 refute 後缺席，少數意見不得消失", minority_vanishes, "requires_human 必須為 true")
    bad("資料分級超出 provider 允許範圍", lambda r: r.update(data_class="confidential"), "不得外傳")
    bad("缺 data_class", lambda r: r.pop("data_class"), "data_class")
    # 輪次結構：範例 findings[0] 的意見為 [claude r1, openai r1, claude r2, openai r2]
    def only_round2(r):        # 拿掉所有第 1 輪：只剩交叉輪，沒有獨立的第一輪
        f = r["findings"][0]; f["opinions"] = [o for o in f["opinions"] if o["round"] != 1]
    def one_key_no_round1(r):  # openai 只有第 2 輪
        f = r["findings"][0]; f["opinions"] = [o for o in f["opinions"] if not (o["provider"] == "openai-cloud" and o["round"] == 1)]
    def skip_round2(r):        # 第 1 輪之後直接跳到第 3 輪
        for o in r["findings"][0]["opinions"]:
            if o["round"] == 2: o["round"] = 3
    def duplicate_round1(r):   # 同一（角色, provider）第 1 輪兩筆
        f = r["findings"][0]; f["opinions"].append(dict(f["opinions"][0], verdict="refute"))
    bad("只有交叉輪、沒有第 1 輪獨立意見", only_round2, "沒有第 1 輪獨立意見")
    bad("某個（角色, provider）缺第 1 輪", one_key_no_round1, "openai-cloud 沒有第 1 輪獨立意見")
    bad("跳過第 2 輪直接第 3 輪", skip_round2, "沒有第 2 輪")
    bad("同一（角色, provider）同一輪多筆意見", duplicate_round1, "每輪只能一筆")
    r_ok = copy.deepcopy(rec)   # 第 1 輪之後缺席（例如逾時）是允許的：只要第 1 輪在、沒有跳輪
    r_ok["findings"][0]["opinions"] = [o for o in r_ok["findings"][0]["opinions"]
                                       if not (o["provider"] == "openai-cloud" and o["round"] == 2)]
    _round_errs = [e for e in evaluate(r_ok, cfg, controls, None)["errors"] if "輪" in e]
    if _round_errs:
        fails.append(f"第 1 輪之後缺席不應觸發輪次錯誤（得到 {_round_errs}）")
    r_rounds = copy.deepcopy(rec)
    # 範例紀錄最多到第 2 輪：上限設為 1（不允許交叉輪）時第 2 輪必須被拒絕
    if not any("輪超過上限" in e for e in evaluate(r_rounds, {**cfg, "max_round": 1}, controls, None)["errors"]):
        fails.append("超過 max_cross_rounds 的輪次必須拒絕")
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
    # 接線（#183）：provider 的 tool 列是 gate_result.tool 的形狀；refused → missing、exit_code 3，其餘照實記錄
    want = [gate_result.tool(p["provider"], "missing" if p["state"] == "refused" else p["state"], version=p.get("model"),
                             exit_code=3 if p["state"] == "refused" else None, output_ref="reviews/g4/x.yaml")
            for p in r6["providers"]]
    got = g6["tools"][-len(r6["providers"]):]
    if got != want or [list(t) for t in got] != [list(t) for t in want]:
        fails.append(f"provider 的 tool 列應為 gate_result.tool 的形狀（refused → missing／exit 3）（得到 {got}）")
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
    # 留言跳脫：受測方字串不得插入連結、圖片、@mention
    _md = comment_markdown({"status": "pending", "status_reason": "x](https://evil.example) ![i](https://e/x.png) @someone <img src=x>"}, None)
    if "@someone" in _md or "](https://evil" in _md or "<img" in _md.replace("\\<img", ""):
        fails.append(f"comment_markdown 應跳脫受測方字串：{_md}")
    # 本 PR 改過的裁決同樣不能自證（M4）
    _rl = {"rulings/a.yaml": {"decided_by": {"handle": "author"}}, "rulings/b.yaml": {"decided_by": {"handle": "someone"}},
           "rulings/c.yaml": {"decided_by": {"handle": "Reviewer"}}}
    _fs = [{"ruling_ref": k} for k in _rl] + [{"ruling_ref": None}]
    _rc = ruling_caps(_fs, lambda ref: True, "author", ["reviewer"], _rl.get)
    if len(_rc) != 2 or not any("a.yaml" in x for x in _rc) or not any("b.yaml" in x for x in _rc):
        fails.append(f"本 PR 改過的裁決：decided_by 是作者或非核准者 → 不可信；核准者 → 可信（得到 {_rc}）")
    if ruling_caps(_fs, lambda ref: False, "author", [], _rl.get):
        fails.append("裁決不是本 PR 引入（已在 base 上）→ 不設上限")
    if record_changed(None, "HEAD", "reviews/g4/x.yaml") is not True or record_changed("", "HEAD", "reviews/g4/x.yaml") is not True:
        fails.append("沒有 base 可比對 → 紀錄應視為本次變更引入（fail closed）")
    # 信任問題交給閘門判定（#213；以前由 apply_cap 在判定之外改寫）：當成待人工裁決「審查紀錄未獲信任：…」。
    # 不算信任問題時會 pass → pending，且 VS-G4-LLM-REVIEW coverage 降為 pending；本來就不是 pass → 狀態與 coverage 不變
    llm_cov = lambda g: next(c for c in g["coverage"] if c["control_id"] == LLM_CONTROL)
    g4p = gate_of(r4, ev4, trust_problems=["x", "y"])
    if g4p["status"] != "pending" or llm_cov(g4p)["state"] != "pending" or llm_cov(g4p)["reason"] != "審查紀錄未獲信任：x" \
            or "待人工裁決：審查紀錄未獲信任：x" not in (g4p["status_reason"] or "") or "待人工裁決：審查紀錄未獲信任：y" not in g4p["status_reason"]:
        fails.append(f"不可信的 pass → pending、理由列為待人工裁決、VS-G4-LLM-REVIEW coverage 降為 pending（得到 {g4p['status']}："
                     f"{g4p['status_reason']}、{llm_cov(g4p)}）")
    gf, _ = derive_gate({**_static(), "findings_count": {"blocking": 1, "advisory": 0}}, r4, ev4, None, "x", trust_problems=["x"])
    if gf["status"] != "fail" or llm_cov(gf)["state"] != "pass" or "審查紀錄未獲信任：x" not in (gf["status_reason"] or ""):
        fails.append(f"信任問題不得把 fail 改掉、本來就不是 pass 時 coverage 不變，但理由仍要寫明（得到 {gf['status']}、{llm_cov(gf)}）")
    if hasattr(sys.modules[__name__], "apply_cap"):
        fails.append("apply_cap 應已移除：狀態只由閘門判定產出")
    # 回傳（閘門結果, 審查發現）：閘門結果不再帶私有欄位 _llm_findings（以前寫檔前要記得 pop）
    g_rh, llm_rh = derive_gate(_static(), rec, ev, None, "x")
    if "_llm_findings" in g_rh or [f["id"] for f in llm_rh] != [fid]:
        fails.append(f"審查發現另外回傳、閘門結果沒有 _llm_findings（得到 {list(g_rh)}、{llm_rh}）")
    # 待裁決的 blocking 發現（#211）：計入 findings_count、status pending、理由用 GateRun.awaiting_blocking 的固定開頭
    r6b = copy.deepcopy(rec); f6b = r6b["findings"][0]
    f6b.update(policy_tier="blocking", requires_human=False, validation_status="pending", ruling_ref=None)
    for o in f6b["opinions"]:
        o.update(verdict="confirm", minority=False)
    g6p = gate_of(r6b, evaluate(r6b, cfg, controls, None))
    if g6p["status"] != "pending" or g6p["findings_count"]["blocking"] != 1 or gate_result.AWAITING_BLOCKING_PREFIX not in (g6p["status_reason"] or ""):
        fails.append(f"待裁決的 blocking → pending、計入 findings_count（得到 {g6p['status']}、{g6p['findings_count']}：{g6p['status_reason']}）")
    # 一份 coverage（#213）：判定看輸出的完整 coverage；紀錄的 untested 經 coverage、pending 仍是未完成原因（status 都是 incomplete）
    ru = copy.deepcopy(r4); ru["coverage"] = [{"control_id": LLM_CONTROL, "state": "untested", "reason": "逾時"}]
    evu = evaluate(ru, cfg, controls, None); gu = gate_of(ru, evu)
    if gu["status"] != "incomplete" or f"{LLM_CONTROL} 未實測（逾時）" not in (gu["status_reason"] or "") \
            or [g["control_id"] for g in evu.get("coverage_gaps") or []] != [LLM_CONTROL]:
        fails.append(f"紀錄 coverage untested → incomplete、經 coverage 寫明、evaluate 回傳結構化缺口（得到 {gu['status']}：{gu['status_reason']}、{evu.get('coverage_gaps')}）")
    rp = copy.deepcopy(r4); rp["coverage"] = [{"control_id": LLM_CONTROL, "state": "pending", "reason": "待補"}]
    evp = evaluate(rp, cfg, controls, None); gp = gate_of(rp, evp)
    if gp["status"] != "incomplete" or f"coverage {LLM_CONTROL}: pending（待補）" not in (gp["status_reason"] or ""):
        fails.append(f"紀錄 coverage pending → 仍是未完成原因、incomplete（不得因判定看 coverage 而變 pass；得到 {gp['status']}：{gp['status_reason']}）")
    if not any(i.startswith(f"coverage {LLM_CONTROL}: untested") for i in evu["incomplete"]):
        fails.append("evaluate 的 incomplete 照舊列出 coverage 缺口（check 子指令的輸出不變）")
    # 控制重複：紀錄 coverage 與靜態檢查同一個控制、或紀錄內重複 → 合併成一筆，state 取較嚴者，理由串接（#213 決定 2）
    rdup = copy.deepcopy(r4); rdup["coverage"] = [{"control_id": LLM_CONTROL, "state": "pass", "reason": None},
                                                {"control_id": "ASVS5-V8.2", "state": "untested", "reason": "LLM 未審"},
                                                {"control_id": LLM_CONTROL, "state": "pending", "reason": "補件"}]
    evdup = evaluate(rdup, cfg, controls, None)
    try:
        gdup, _ = derive_gate({**_static(), "coverage": [{"control_id": "ASVS5-V8.2", "state": "pass", "reason": None},
                                                         {"control_id": LLM_CONTROL, "state": "pending", "reason": "x"}]},
                              rdup, evdup, None, "x")
    except ValueError as e:   # 沒有合併時 GateRun 會拒絕重複的控制
        gdup = {"coverage": [], "status": f"例外 {e}"}
    cov = [(c["control_id"], c["state"]) for c in gdup["coverage"]]
    if cov != [("ASVS5-V8.2", "untested"), (LLM_CONTROL, "pending")] or gdup["status"] != "incomplete":
        fails.append(f"重複的控制合併成一筆、取較嚴的 state（得到 {cov}、{gdup['status']}）")
    r6 = copy.deepcopy(r4); r6["recorded_by"]["handle"] = ""
    ev6 = evaluate(r6, cfg, controls, None)
    if ev6["errors"] or not any("handle 未填" in i for i in ev6["incomplete"]):
        fails.append("handle 空白：schema 應接受（harness 照 SKILL 留空），但列為缺口")
    if "pending" not in comment_markdown(gate_of(rec, ev), "x", llm_rh) or fid not in comment_markdown(gate_of(rec, ev), "x", llm_rh):
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
    # 政策讀不到 → 無法判定紀錄是否可信（fail closed）：合法、已 approve 的紀錄也不可信
    got = external_trust({ref: ext}, "author", ["reviewer"], cfg, controls, policy_load=broken)
    if not any(vibesec_policy.POLICY_UNREADABLE in x for x in got):
        fails.append(f"外部紀錄：政策讀不到 → 應不可信並寫明原因（得到 {got}）")
    # gate 子指令的退出碼依受信任政策的 mode（#201；以前取 --mode、預設 shadow）：閘門結果是 fail 時，政策 enforce → exit 1、
    # 政策 shadow → exit 0。--mode 已移除（#203，ADR 0002）：傳了 → argparse exit 2
    import contextlib, io, tempfile as _tf
    import vibesec_policy
    real_load = vibesec_policy.load_policy
    with _tf.TemporaryDirectory() as d:
        failing = dict(_static(), status="fail", findings_count={"blocking": 1, "advisory": 0},
                       coverage=[{"control_id": "VS-G4-RULES-FILE-UNICODE", "state": "fail", "reason": None},
                                 {"control_id": LLM_CONTROL, "state": "pending", "reason": "x"}])
        sp = pathlib.Path(d, "static.json"); sp.write_text(json.dumps(failing), encoding="utf-8")
        try:
            for mode, want in (("enforce", 1), ("shadow", 0)):
                with vibesec_policy.mode_policy_root(f"mode: {mode}") as pr:
                    vibesec_policy.load_policy = lambda root=None, **kw: real_load(pr, **kw)
                    out = pathlib.Path(d, f"gate-{mode}.json")
                    with contextlib.redirect_stdout(io.StringIO()):
                        rc = main(["gate", "--static", str(sp), "--head", "HEAD", "--out", str(out)])
                g = json.loads(out.read_text(encoding="utf-8")) if out.is_file() else {}
                if rc != want or g.get("status") != "fail":
                    fails.append(f"gate：閘門結果 fail、政策 {mode} → exit {want}（得到 exit {rc}、{g.get('status')}）")
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    rc = main(["gate", "--static", str(sp), "--head", "HEAD", "--mode", "shadow"])
            except SystemExit as e:
                rc = e.code
            if rc != 2:
                fails.append(f"gate：帶已移除的 --mode → argparse exit 2（得到 {rc}）")
        finally:
            vibesec_policy.load_policy = real_load
    # 退出碼與阻擋判定一致（#214）：enforce 下閘門 fail，或有 blocking 計數（含待裁決的 blocking 發現）→ 1；以前只看 fail，
    # 待裁決的 blocking 在這一步 exit 0、要到 summary 才擋
    pend_b = {"status": "pending", "findings_count": {"blocking": 1, "advisory": 0}}
    for gate, mode, want in [(pend_b, "enforce", 1), (pend_b, "shadow", 0), ({"status": "fail", "findings_count": {"blocking": 0}}, "enforce", 1),
                             ({"status": "pending", "findings_count": {"blocking": 0}}, "enforce", 0),
                             ({"status": "incomplete", "findings_count": {"blocking": 0}}, "enforce", 0),
                             ({"status": "pass", "findings_count": {"blocking": 0}}, "enforce", 0)]:
        try:
            got = gate_exit_code(gate, mode)
        except Exception as e:
            got = f"例外 {type(e).__name__}"
        if got != want:
            fails.append(f"gate 的退出碼：{gate['status']}、blocking {gate['findings_count']['blocking']}、{mode} → {want}（得到 {got}）")
    return fails


# ------------------------------------------------------------------ CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("check"); c.add_argument("record"); c.add_argument("--head", default="HEAD"); c.add_argument("--no-git", action="store_true")
    g = sub.add_parser("gate"); g.add_argument("--static", required=True); g.add_argument("--head", required=True)
    g.add_argument("--out"); g.add_argument("--comment")   # 退出碼依受信任政策的 mode，沒有 --mode（ADR 0002、#203）
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
    trust = []   # CI 的信任問題：紀錄或裁決由本 PR 引入，確認者必須是在目前 head 上 approve 的非作者
    if record is not None:
        changed = record_changed(a.base, head, ref)
        cap = trust_cap(changed, record["recorded_by"].get("handle", ""), a.pr_author,
                        [x for x in a.approvers.split(",") if x])
        if cap and not a.base:
            cap = "無 base 可比對（非 pull_request 事件），無法確認紀錄不是本次變更引入；" + cap
        trust += [cap] if cap else []
        trust += ruling_caps(ev["findings"] if ev else [], lambda ref: record_changed(a.base, head, ref), a.pr_author,
                             [x for x in a.approvers.split(",") if x], lambda ref: _yaml(PROJECT / ref))
    gate, llm_findings = derive_gate(static, record, ev, reason, ref, trust_problems=trust)
    md = comment_markdown(gate, ref, llm_findings)
    if a.out:
        pathlib.Path(a.out).write_text(json.dumps(gate, ensure_ascii=False, indent=2), encoding="utf-8")
    if a.comment:
        pathlib.Path(a.comment).write_text(md, encoding="utf-8")
    print(f"G4 {gate['status']}：{gate.get('status_reason')}")
    # 退出碼依受信任政策的 mode（#201；以前取 --mode、預設 shadow）。政策讀不到 → mode 不明 → 視同 enforce（較嚴）
    from vibesec_policy import effective_mode, load_policy
    return gate_exit_code(gate, effective_mode(load_policy(ROOT)[0]))


if __name__ == "__main__":
    sys.exit(main())
