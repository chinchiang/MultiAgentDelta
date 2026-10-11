#!/usr/bin/env python3
"""三組比較（docs/12 §三）的評分：讀 prepare_comparison.py 的 plan.json、收集到的 review_provider.py 輸出與 answer-key.json。

  python3 scripts/compare_reviews.py --dir reports/comparison/run-01 [--key <answer-key.json>] \\
      [--rulings rulings.json] [--out reports/comparison/run-01/comparison.json]
  python3 scripts/compare_reviews.py selftest

規則：
  - 每次 call 的 state 照實計數：ran／missing／timeout／error／refused。輸出檔不存在 = missing（未收集）；
    不是 JSON、state 不明、provider／role／data_class 與計畫不符、ran 但 verdict 不合法 = error。
  - 只有 ran 的意見參與判定。任一 agent 沒有 ran → 該組該案例記 incomplete，不算對、也不算 clear（incomplete ≠ pass，規則 2）。
  - verdict 對應：confirm = flag、refute = clear、uncertain = 未判定。多代理組全部 ran 且一致才有結論；
    不一致或有 uncertain → requires_human，保留每個意見與少數意見，不多數決（規則 6）。
    --rulings 可提供人工裁決 {"<組>/<packet_id>": "flag"|"clear"}，來源標 human。
  - recall／precision 只以有結論的案例計算，並附 Wilson 95% 區間與分母；另列 coverage（有結論／全部）。
  - 不做綜合分數；不讀模型自評信心（規則 4）。三組有任一 call 不是 ran 或有未裁決分歧 → 狀態不是 complete，不宣稱增益。
離開碼：0 complete；2 incomplete 或 pending_human；4 參數或輸入檔錯誤。
"""
from __future__ import annotations
import argparse, hashlib, json, math, pathlib, sys, tempfile

STATES = ("ran", "missing", "timeout", "error", "refused")
VERDICT = {"confirm": "flag", "refute": "clear", "uncertain": "uncertain"}


def wilson(k: int, n: int):
    if not n: return None
    z = 1.96; p = k / n; d = 1 + z * z / n
    mid, half = (p + z * z / (2 * n)) / d, z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return [round(mid - half, 4), round(mid + half, 4)]


def read_output(call: dict, root: pathlib.Path) -> dict:
    """一次 call 的狀態與 verdict；只取 verdict，其餘意見內容（含任何信心欄位）不參與評分。"""
    path = root / call["out"]
    if not path.is_file(): return {"state": "missing", "note": "輸出檔不存在（未執行或未收集）"}
    try: res = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e: return {"state": "error", "note": f"輸出檔無法解析：{e}"[:200]}
    if not isinstance(res, dict) or res.get("state") not in STATES: return {"state": "error", "note": "輸出缺合法 state"}
    bad = [k for k in ("provider", "role", "data_class") if res.get(k) != call[k]]
    if bad: return {"state": "error", "note": f"輸出與計畫不符：{bad}（{[res.get(k) for k in bad]} ≠ {[call[k] for k in bad]}）"}
    if res["state"] != "ran": return {"state": res["state"], "note": res.get("note")}
    v = (res.get("opinion") or {}).get("verdict") if isinstance(res.get("opinion"), dict) else None
    if v not in VERDICT: return {"state": "error", "note": f"ran 但 verdict 不合法：{v!r}"}
    return {"state": "ran", "verdict": VERDICT[v], "model": res.get("model")}


def confusion(rows: list[tuple[bool, str]]) -> dict:
    tp = sum(1 for t, d in rows if t and d == "flag"); fn = sum(1 for t, d in rows if t and d == "clear")
    fp = sum(1 for t, d in rows if not t and d == "flag"); tn = sum(1 for t, d in rows if not t and d == "clear")
    return {"TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "recall": round(tp / (tp + fn), 4) if tp + fn else None, "recall_n": tp + fn, "recall_95_interval": wilson(tp, tp + fn),
            "precision": round(tp / (tp + fp), 4) if tp + fp else None, "precision_n": tp + fp, "precision_95_interval": wilson(tp, tp + fp)}


def compare(plan: dict, key: dict, root: pathlib.Path, rulings: dict | None = None, plan_raw: bytes | None = None) -> dict:
    rulings, problems = rulings or {}, []
    if plan_raw is not None and hashlib.sha256(plan_raw).hexdigest() != key.get("plan_sha256"): problems.append("plan.json 與 answer-key.json 的 plan_sha256 不符")
    truth = {pid: v["should_flag"] for pid, v in (key.get("cases") or {}).items()}
    for pid, v in (key.get("cases") or {}).items():
        p = root / "packets" / f"{pid}.json"
        if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() != v.get("packet_sha256"): problems.append(f"{pid} 審查包指紋與 answer-key 不符")
    calls = plan.get("calls") or []
    unknown = sorted({c["packet_id"] for c in calls} - set(truth))
    if unknown: problems.append(f"計畫中有 {len(unknown)} 個 packet 不在 answer-key")
    for k, v in rulings.items():
        if v not in ("flag", "clear"): problems.append(f"人工裁決 {k} 必須是 flag／clear，目前 {v!r}")
    got = {(c["arm"], c["packet_id"], c["agent"]): {**read_output(c, root), "provider": c["provider"], "family": c["family"]} for c in calls}
    arms, per_case = {}, {}
    for arm in sorted(plan.get("arms") or {}):
        agents = [a["agent"] for a in plan["arms"][arm]["agents"]]
        pids = sorted({c["packet_id"] for c in calls if c["arm"] == arm and c["packet_id"] in truth})
        states = {s: 0 for s in STATES}; outcome = {"decided": 0, "incomplete": 0, "uncertain": 0, "requires_human": 0}
        rows, disputes, unanimous, pairs, pair_agree = [], [], 0, 0, 0
        agent_rows = {a: [] for a in agents}
        for pid in pids:
            ops = {a: got.get((arm, pid, a), {"state": "missing", "note": "計畫缺此 call"}) for a in agents}
            for o in ops.values(): states[o["state"]] += 1
            ran = {a: o for a, o in ops.items() if o["state"] == "ran"}
            for a, o in ran.items():
                if o["verdict"] != "uncertain": agent_rows[a].append((truth[pid], o["verdict"]))
            entry = {"opinions": {a: {"state": o["state"], "verdict": o.get("verdict"), "provider": o["provider"], "family": o["family"],
                                      **({"note": o["note"]} if o.get("note") else {})} for a, o in ops.items()}}
            if len(ran) < len(agents):
                entry["outcome"] = "incomplete"; outcome["incomplete"] += 1
            else:
                vs = [o["verdict"] for o in ran.values()]
                if len(vs) > 1:
                    for i in range(len(vs)):
                        for j in range(i + 1, len(vs)): pairs += 1; pair_agree += vs[i] == vs[j]
                    unanimous += len(set(vs)) == 1
                if len(set(vs)) == 1 and vs[0] != "uncertain":
                    entry.update(outcome="decided", decision=vs[0], source="unanimous" if len(vs) > 1 else "single")
                else:
                    kind = "uncertain" if len(vs) == 1 else "requires_human"
                    counts = {v: vs.count(v) for v in set(vs)}
                    entry.update(outcome=kind, requires_human=True,
                                 minority=sorted(a for a, o in ran.items() if counts[o["verdict"]] < max(counts.values())))
                    r = rulings.get(f"{arm}/{pid}")
                    if r in ("flag", "clear"): entry.update(outcome="decided", decision=r, source="human")
                    else: outcome[kind] += 1; disputes.append(pid)
                if entry["outcome"] == "decided": outcome["decided"] += 1; rows.append((truth[pid], entry["decision"]))
            per_case.setdefault(pid, {})[arm] = entry
        arms[arm] = {"label": plan["arms"][arm].get("label"), "families": plan["arms"][arm].get("families"), "packets": len(pids),
                     "call_states": states, "outcomes": outcome, "coverage": round(outcome["decided"] / len(pids), 4) if pids else None,
                     **confusion(rows),
                     "agreement": None if len(agents) < 2 else {"unanimous_rate": round(unanimous / max(1, len(pids) - outcome["incomplete"]), 4)
                                                                if len(pids) > outcome["incomplete"] else None,
                                                                "pairwise_rate": round(pair_agree / pairs, 4) if pairs else None, "pairs": pairs},
                     "per_agent": {x["agent"]: {"provider": x["provider"], "role": x["role"], **confusion(agent_rows[x["agent"]])} for x in plan["arms"][arm]["agents"]},
                     "unresolved": disputes}
    # 共同漏報：三組都有結論且都判 clear 的正例；每個 agent 的新增有效發現：A 沒抓到（clear／uncertain），該 agent 判 flag 的正例
    decided_all = [pid for pid, e in per_case.items() if set(e) == set(arms) and all(x["outcome"] == "decided" for x in e.values())]
    common_fn = sorted(pid for pid in decided_all if truth[pid] and all(x["decision"] == "clear" for x in per_case[pid].values()))
    additional = {}
    for pid, e in per_case.items():
        a = e.get("A")
        if not truth[pid] or a is None or a["outcome"] == "incomplete" or a.get("decision") == "flag": continue
        for arm, x in e.items():
            if arm == "A": continue
            for ag, o in x["opinions"].items():
                if o["verdict"] == "flag": additional.setdefault(ag, []).append(pid)
    not_ran = sum(v["call_states"][s] for v in arms.values() for s in STATES if s != "ran")
    pending = sum(len(v["unresolved"]) for v in arms.values())
    if not_ran: problems.append(f"{not_ran} 次 call 不是 ran（見 call_states）")
    status = "incomplete" if problems or not arms else ("pending_human" if pending else "complete")
    case_ids = {pid: key["cases"][pid]["case_id"] for pid in per_case if pid in key.get("cases", {})}
    return {"status": status, "problems": problems, "arms": arms, "common_false_negatives": [case_ids[p] for p in common_fn],
            "additional_valid_vs_single": {ag: sorted(case_ids[p] for p in v) for ag, v in sorted(additional.items())},
            "cases": {case_ids.get(pid, pid): {"packet_id": pid, "should_flag": truth.get(pid), **e} for pid, e in sorted(per_case.items())},
            "dataset_sha256": key.get("dataset_sha256"), "split": key.get("split"), "data_class": plan.get("data_class"),
            "note": "各組分開列出，不做綜合分數；不讀模型自評信心。只有三組 status=complete 且分母相同時才比較召回率；"
                    "合成 selftest 不是實驗結果。費用與人工確認時間另由人工紀錄，不在此補造。"}


# ------------------------------------------------------------------ selftest
def selftest() -> list[str]:
    import importlib.util
    spec = importlib.util.spec_from_file_location("prepare_comparison", pathlib.Path(__file__).with_name("prepare_comparison.py"))
    pc = importlib.util.module_from_spec(spec); spec.loader.exec_module(pc)
    cases, split, prov, arms = pc._fixture()
    cases = [c for c in cases if c["id"] in ("g3-sqli-pos-01", "g3-sqli-neg-01")] + \
            [{"id": "g3-cmdi-pos-01", "gate": "G3", "domain": "general_vulnerabilities", "title": "命令注入正例",
              "input": {"kind": "code", "snippet": "os.system('ping ' + h)"}, "expected": {"should_flag": True}, "held_out": True}]
    split = {"held_out": [c["id"] for c in cases]}
    r = pc.build(cases, split, prov, arms, "internal", "held_out", "00" * 16)
    plan, key, fails = r["plan"], r["key"], []
    pid = {v["case_id"]: p for p, v in key["cases"].items()}
    sq, neg, cm = pid["g3-sqli-pos-01"], pid["g3-sqli-neg-01"], pid["g3-cmdi-pos-01"]
    with tempfile.TemporaryDirectory() as d:
        root = pathlib.Path(d) / "exp"; pc.write(r, root)
        def put(arm, p, agent, verdict=None, state="ran", **over):
            c = next(x for x in plan["calls"] if (x["arm"], x["packet_id"], x["agent"]) == (arm, p, agent))
            out = {"provider": c["provider"], "role": c["role"], "data_class": c["data_class"], "state": state, "model": "m",
                   "opinion": {"verdict": verdict, "rationale": "x", "cited_evidence": [], "confidence": 0.99} if verdict else None, **over}
            f = root / c["out"]; f.parent.mkdir(parents=True, exist_ok=True); f.write_text(json.dumps(out))
        # 全部 ran：A 漏 cmdi；B 一致；C 兩個 agent 都抓到
        for p, v in ((sq, "confirm"), (neg, "refute"), (cm, "refute")): put("A", p, "A1", v)
        for p, v in ((sq, "confirm"), (neg, "refute"), (cm, "refute")): put("B", p, "B1", v); put("B", p, "B2", v)
        for p, v in ((sq, "confirm"), (neg, "refute"), (cm, "confirm")): put("C", p, "C1", v); put("C", p, "C2", v)
        raw = (root / "plan.json").read_bytes()
        rep = compare(plan, key, root, plan_raw=raw)
        if rep["status"] != "complete": fails.append(f"全部 ran 且一致應為 complete：{rep['status']} {rep['problems']}")
        if (rep["arms"]["A"]["recall"], rep["arms"]["A"]["precision"], rep["arms"]["C"]["recall"]) != (0.5, 1.0, 1.0): fails.append(f"recall／precision：{rep['arms']}")
        if rep["arms"]["A"]["recall_n"] != 2 or rep["arms"]["B"]["agreement"]["pairwise_rate"] != 1.0: fails.append("分母與一致率")
        if rep["common_false_negatives"] != [] or rep["additional_valid_vs_single"] != {"C1": ["g3-cmdi-pos-01"], "C2": ["g3-cmdi-pos-01"]}:
            fails.append(f"共同漏報／新增有效發現：{rep['common_false_negatives']} {rep['additional_valid_vs_single']}")
        if "confidence" in json.dumps(rep): fails.append("報告不得帶出模型自評信心")
        # 分歧：不多數決、保留少數意見；人工裁決後才有結論
        put("C", cm, "C2", "refute")
        rep = compare(plan, key, root)
        e = rep["cases"]["g3-cmdi-pos-01"]["C"]
        if rep["status"] != "pending_human" or e["outcome"] != "requires_human" or not e.get("requires_human") or rep["arms"]["C"]["recall_n"] != 1:
            fails.append(f"分歧應 requires_human 且不計分：{rep['status']} {e}")
        if set(e["opinions"]) != {"C1", "C2"} or e["opinions"]["C2"]["verdict"] != "clear": fails.append(f"兩個意見都要保留：{e}")
        rep = compare(plan, key, root, rulings={f"C/{cm}": "flag"})
        if rep["status"] != "complete" or rep["cases"]["g3-cmdi-pos-01"]["C"]["source"] != "human": fails.append("人工裁決後應有結論，來源 human")
        put("A", cm, "A1", "uncertain"); rep = compare(plan, key, root)
        if rep["arms"]["A"]["outcomes"]["uncertain"] != 1 or rep["arms"]["A"]["FN"] != 0: fails.append("uncertain 不算 clear／FN")
        put("A", cm, "A1", "refute")
        # missing／timeout／error／refused：照實計數，不算對、不算 negative
        (root / next(x["out"] for x in plan["calls"] if (x["arm"], x["packet_id"], x["agent"]) == ("B", neg, "B2"))).unlink()
        put("B", sq, "B1", state="timeout"); put("C", neg, "C1", state="refused", note="no provider allowed")
        put("C", sq, "C1", "confirm", provider="other")   # provider 與計畫不符
        put("A", sq, "A1", state="error")
        rep = compare(plan, key, root, rulings={f"C/{cm}": "flag"})
        st = {a: rep["arms"][a]["call_states"] for a in "ABC"}
        if rep["status"] != "incomplete" or st["B"]["missing"] != 1 or st["B"]["timeout"] != 1 or st["C"]["refused"] != 1 or st["C"]["error"] != 1 or st["A"]["error"] != 1:
            fails.append(f"狀態計數：{rep['status']} {st}")
        b = rep["arms"]["B"]
        if b["outcomes"]["incomplete"] != 2 or b["TN"] != 0 or b["TP"] != 0 or b["recall_n"] != 1: fails.append(f"缺意見不得算 TP／TN：{b}")
        if rep["arms"]["A"]["TP"] != 0 or rep["arms"]["A"]["recall_n"] != 1: fails.append("error 不得算對")
        # 竄改：審查包或計畫指紋不符 → incomplete
        (root / "packets" / f"{neg}.json").write_text("{}")
        if not any("指紋" in p for p in compare(plan, key, root, plan_raw=raw + b" ")["problems"]): fails.append("指紋不符要列為問題")
        (root / next(x["out"] for x in plan["calls"] if x["agent"] == "A1" and x["packet_id"] == neg)).write_text("not json")
        if compare(plan, key, root)["cases"]["g3-sqli-neg-01"]["A"]["opinions"]["A1"]["state"] != "error": fails.append("無法解析的輸出應為 error")
    if wilson(0, 0) is not None or wilson(5, 5)[1] != 1.0: fails.append("wilson 區間")
    return fails


def main(argv: list[str]) -> int:
    if argv[1:2] == ["selftest"]:
        fails = selftest()
        for f in fails: print(f"FAIL {f}")
        print("selftest " + ("通過" if not fails else f"失敗 {len(fails)} 項"))
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description="三組比較評分（不呼叫模型）")
    ap.add_argument("--dir", required=True, type=pathlib.Path, help="prepare_comparison.py 的 --out 目錄")
    ap.add_argument("--key", type=pathlib.Path, help="answer-key.json；預設 <dir>/answer-key.json")
    ap.add_argument("--rulings", type=pathlib.Path, help='人工裁決 JSON：{"<組>/<packet_id>": "flag"|"clear"}')
    ap.add_argument("--out", type=pathlib.Path, help="報告 JSON；預設 <dir>/comparison.json")
    a = ap.parse_args(argv[1:])
    try:
        raw = (a.dir / "plan.json").read_bytes()
        rep = compare(json.loads(raw), json.loads((a.key or a.dir / "answer-key.json").read_text(encoding="utf-8")), a.dir,
                      json.loads(a.rulings.read_text(encoding="utf-8")) if a.rulings else None, raw)
    except (OSError, ValueError, KeyError) as e:
        print(f"錯誤：{e}", file=sys.stderr); return 4
    out = a.out or a.dir / "comparison.json"
    out.write_text(json.dumps(rep, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    for arm, v in rep["arms"].items():
        print(f"{arm} {v['label']}: states={v['call_states']} outcomes={v['outcomes']} recall={v['recall']}（n={v['recall_n']}）"
              f" precision={v['precision']}（n={v['precision_n']}）")
    print(f"status={rep['status']}" + "".join(f"\n  - {p}" for p in rep["problems"]) + f" → {out}")
    return 0 if rep["status"] == "complete" else 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
