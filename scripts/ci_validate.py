#!/usr/bin/env python3
"""VibeSec：在本機重現 PR CI repo-validate 的三次 validate（#238）。

PR CI 跑三次 validate：
  1. PR 版本：                 python3 scripts/validate.py
  2. 受信任樹版本驗受驗樹：    VIBESEC_PROJECT_ROOT=<受驗樹> python3 <受信任樹>/scripts/validate.py（抓版本錯開，#207、#235）
  3. PR 版本、mode 改成 enforce 的副本（抓依賴 repo 目前 mode 的 selftest，#223）
workflow 文件第 5 步要求三次都 0 錯誤；以前本機只跑第 1 種。

用法：
  python3 -I scripts/ci_validate.py --trusted /tmp/wt-main     # --trusted：受信任樹，通常是 workflow 第 0 步的 main worktree
  python3 scripts/ci_validate.py selftest
退出碼：0 三次都 0 錯誤；1 有錯誤；2 無法判定（--trusted 不對、validate 崩潰、找不到摘要行、副本建不起來、
       受信任樹的 validate 不認 VIBESEC_PROJECT_ROOT；incomplete ≠ pass）。argparse 用法錯誤同樣是 2。
"""
from __future__ import annotations
import argparse, contextlib, os, pathlib, re, shutil, subprocess, sys, tempfile
from typing import NamedTuple

ROOT = pathlib.Path(__file__).resolve().parent.parent
PYTHON = sys.executable or "python3"
TIMEOUT = 600   # 每次 validate 最多 10 分鐘（CI 的 repo-validate job 是 timeout-minutes: 10）
# 三次 validate 都帶這個環境變數：validate 會跑所有 selftest，若任何地方意外又呼叫了本腳本的 main，就直接退出碼 2，不遞迴
RUNNING = "VIBESEC_CI_VALIDATE_RUNNING"


class Summary(NamedTuple):
    passed: int
    warnings: int
    errors: int
    err_lines: list


def parse(output: str) -> Summary | None:
    """validate 輸出 → Summary；摘要行不是剛好一行 → None（不能當成 0 錯誤）。"""
    found = re.findall(r"^通過 (\d+) 項；警告 (\d+)；錯誤 (\d+)$", output, re.M)
    if len(found) != 1:
        return None
    passed, warns, errs = (int(x) for x in found[0])
    return Summary(passed, warns, errs, [ln for ln in output.splitlines() if ln.lstrip().startswith("ERR ")])


class CopyProblem(Exception):
    """建不起 enforce 副本（不是 git 樹、複製失敗、mode 行找不到或改不成功）：第 3 次記為無法判定。"""


# CI repo-validate「mode 改為 enforce 的副本」那一步的 inline Python；CI 改了這裡也要跟著改（CI 不能 import PR 樹的模組）
SET_ENFORCE = ("import pathlib, sys; sys.path.insert(0, sys.argv[1] + '/scripts'); from vibesec_policy import set_mode_line; "
               "set_mode_line(pathlib.Path(sys.argv[1]) / 'vibesec.yaml', 'mode: enforce')")


@contextlib.contextmanager
def enforce_copy(project: pathlib.Path):
    """project 的副本，內容對齊 CI checkout 出來的樹：git 追蹤的檔案（取工作目錄的內容，含尚未 commit 的修改）、
    尚未 git add 的新檔，以及 .git（排除它會讓 g0 selftest 失敗）；.gitignore 排除的檔案與 _trusted/ 不複製。
    以副本自己的 vibesec_policy.set_mode_line 改 mode，並確認以 mode: 開頭的行剛好一行 `mode: enforce`
    （比 CI 的 grep -qx 嚴：重複的 mode 行也算失敗）。yield 副本根目錄，離開時刪除。失敗 → CopyProblem。"""
    project = pathlib.Path(project)
    d = pathlib.Path(tempfile.mkdtemp(prefix="vibesec-enforce-"))
    try:
        copy = d / "tree"
        try:
            ls = subprocess.run(["git", "-C", str(project), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                                capture_output=True, check=True)
            files = [f for f in ls.stdout.decode("utf-8", "surrogateescape").split("\0") if f and not f.startswith("_trusted/")]
            for rel in files:
                src, dst = project / rel, copy / rel
                if not os.path.lexists(src):   # 已刪除但還在索引裡的檔案：工作目錄沒有它，副本也不要有
                    continue
                dst.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(src, dst, follow_symlinks=False)
            shutil.copytree(project / ".git", copy / ".git", symlinks=True)
        except (OSError, shutil.Error, subprocess.CalledProcessError) as e:
            raise CopyProblem(f"複製 {project} 失敗（需要是 git 樹）：{e}") from e
        r = subprocess.run([PYTHON, "-I", "-c", SET_ENFORCE, str(copy)], capture_output=True, text=True)
        lines = (copy / "vibesec.yaml").read_text(encoding="utf-8").splitlines() if (copy / "vibesec.yaml").is_file() else []
        if r.returncode != 0 or [ln for ln in lines if ln.startswith("mode:")] != ["mode: enforce"]:
            last = (r.stderr or r.stdout).strip().splitlines()[-1:] or ["（沒有輸出）"]
            raise CopyProblem(f"無法把副本的 mode 改成 enforce：{last[0]}")
        yield copy
    finally:
        shutil.rmtree(d, ignore_errors=True)


def run_all(project: pathlib.Path, trusted: pathlib.Path, *, runner, make_copy, environ=None) -> tuple[int, list[str]]:
    """依序跑三次 validate，回傳 (退出碼, 輸出行)。runner(cmd, cwd=, env=) -> (退出碼, 輸出)；
    make_copy(project) 是 context manager，yield mode 改成 enforce 的副本根目錄，建不起來 → CopyProblem；
    environ 預設 os.environ（selftest 注入）。任何一次無法判定（找不到唯一的摘要行、退出碼和摘要不一致、
    副本建不起來、受信任樹的 validate 不認 VIBESEC_PROJECT_ROOT）→ 2，優先於有錯誤 → 1。"""
    project, trusted = pathlib.Path(project).resolve(), pathlib.Path(trusted).resolve()
    if not trusted.is_dir():
        return 2, [f"--trusted {trusted} 不存在（通常是 workflow 第 0 步建立的 main worktree）"]
    trusted_validate = trusted / "scripts/validate.py"
    if not trusted_validate.is_file():
        return 2, [f"--trusted {trusted} 沒有 scripts/validate.py：不是受信任樹（通常是 workflow 第 0 步的 main worktree）"]
    environ = os.environ if environ is None else environ
    # 第 1、3 次不得被呼叫端的 VIBESEC_PROJECT_ROOT 誤導；三次都帶 RUNNING，讓巢狀的 ci_validate 停下來
    base = {**{k: v for k, v in environ.items() if k != "VIBESEC_PROJECT_ROOT"}, RUNNING: "1"}
    results, lines = [], []

    def run_one(label, cmd, cwd, env):
        rc, out = runner(cmd, cwd=cwd, env=env)
        r = parse(out)
        lines.append(f"== {label}")
        if r is None or rc != (1 if r.errors else 0):
            tail = out.strip().splitlines()[-3:]
            lines.extend([f"  無法判定（退出碼 {rc}，找不到唯一的摘要行或和退出碼不一致）：", *(f"    {x}" for x in tail)])
            results.append((label, None))
            return
        lines.append(f"  通過 {r.passed} 項；警告 {r.warnings}；錯誤 {r.errors}")
        lines.extend(r.err_lines)
        results.append((label, r.errors))

    run_one("PR 版", [PYTHON, str(project / "scripts/validate.py")], project, base)
    label = "受信任樹版驗受驗樹"
    if "VIBESEC_PROJECT_ROOT" in trusted_validate.read_text(encoding="utf-8", errors="replace"):
        run_one(label, [PYTHON, str(trusted_validate)], project, {**base, "VIBESEC_PROJECT_ROOT": str(project)})
    else:   # CI 遇到這種舊樹會警告並略過；本機 fail closed：它會去驗受信任樹本身，結果不代表受驗樹
        lines.extend([f"== {label}", "  無法判定：受信任樹的 validate.py 不認 VIBESEC_PROJECT_ROOT（會去驗受信任樹本身）"])
        results.append((label, None))
    try:
        with make_copy(project) as copy:
            run_one("enforce 副本", [PYTHON, str(pathlib.Path(copy) / "scripts/validate.py")], copy, base)
    except CopyProblem as e:
        lines.extend(["== enforce 副本", f"  無法建立副本：{e}"])
        results.append(("enforce 副本", None))
    lines.append("== 彙總：" + "、".join(f"{lb} {'無法判定' if n is None else f'錯誤 {n}'}" for lb, n in results))
    if any(n is None for _, n in results):
        return 2, lines + ["結論：無法判定（incomplete ≠ pass）"]
    if any(n for _, n in results):
        return 1, lines + ["結論：有錯誤"]
    return 0, lines + ["結論：三次都 0 錯誤"]


def selftest() -> list[str]:
    fails: list[str] = []

    def check(name, fn):
        """fn 回傳 None 表示通過；回傳字串或拋例外表示失敗。"""
        try:
            why = fn()
        except Exception as e:
            why = f"{type(e).__name__}：{e}"
        if why:
            fails.append(f"{name}：{why}")

    def t_parse():
        out = "...\n通過 378 項；警告 1；錯誤 2\n  WARN 某警告\n  ERR  a：壞了\n  ERR  b：也壞了\n"
        if parse(out) != (378, 1, 2, ["  ERR  a：壞了", "  ERR  b：也壞了"]):
            return f"摘要行與 ERR 行（得到 {parse(out)}）"
        if parse("ERROR: PyYAML 未安裝，無法驗證（incomplete ≠ pass）\n") is not None:
            return "找不到摘要行 → None（不是 0 錯誤）"
        if parse("通過 1 項；警告 0；錯誤 0\n通過 2 項；警告 0；錯誤 0\n") is not None:
            return "摘要行不只一行 → None（輸出不可信）"
    check("parse：取出摘要行與 ERR 行", t_parse)

    # ---- run_all：runner(cmd, cwd=, env=) 與 make_copy(project) 都注入（selftest 不能真的跑 validate：validate 會跑所有 selftest）
    OK = "通過 5 項；警告 0；錯誤 0\n"
    BAD = "通過 4 項；警告 0；錯誤 1\n  ERR  docs/x.md：壞了\n"

    def fake(outputs, calls):
        """outputs：{'pr'|'trusted'|'enforce': (退出碼, 輸出)}；依呼叫的 validate 判斷是哪一次。"""
        def runner(cmd, *, cwd, env):
            which = "trusted" if "TRUSTED" in str(cmd[-1]) else "enforce" if "COPY" in str(cwd) else "pr"
            calls.append((which, pathlib.Path(cwd), env.get("VIBESEC_PROJECT_ROOT")))
            return outputs[which]
        return runner

    def copier(fail=False):
        @contextlib.contextmanager
        def make_copy(project):
            if fail:
                raise CopyProblem("找不到唯一的最上層 mode")
            yield pathlib.Path(project).parent / "COPY"
        return make_copy

    def run_scenario(outputs, *, fail_copy=False, trusted="ok", environ=None):
        """trusted：ok＝受信任樹的 validate 認得 VIBESEC_PROJECT_ROOT；old＝不認得；none＝沒有 validate；missing＝路徑不存在。"""
        with tempfile.TemporaryDirectory() as d:
            proj, tr = pathlib.Path(d, "project"), pathlib.Path(d, "TRUSTED")
            (proj / "scripts").mkdir(parents=True)
            if trusted != "missing":
                (tr / "scripts").mkdir(parents=True)
            if trusted in ("ok", "old"):
                (tr / "scripts/validate.py").write_text("ROOT = 'VIBESEC_PROJECT_ROOT'\n" if trusted == "ok" else "ROOT = '.'\n")
            calls = []
            rc, lines = run_all(proj, tr, runner=fake(outputs, calls), make_copy=copier(fail_copy),
                                environ={"PATH": "/usr/bin"} if environ is None else environ)
            return rc, "\n".join(lines), calls, proj, tr

    def t_run_ok():
        rc, out, calls, proj, tr = run_scenario({"pr": (0, OK), "trusted": (0, OK), "enforce": (0, OK)})
        if rc != 0 or [c[0] for c in calls] != ["pr", "trusted", "enforce"]:
            return f"三次都 0 錯誤 → 退出碼 0、依序跑三次（得到 {rc}、{calls}）"
        if [c[2] for c in calls] != [None, str(proj), None] or calls[1][1] != proj or calls[2][1] != proj.parent / "COPY":
            return f"只有第 2 次帶 VIBESEC_PROJECT_ROOT＝受驗樹；第 3 次在副本執行（得到 {calls}）"
    check("run_all：三次都 0 錯誤", t_run_ok)

    def t_run_errors():
        rc, out, calls, proj, tr = run_scenario({"pr": (0, OK), "trusted": (1, BAD), "enforce": (0, OK)})
        if rc != 1 or "  ERR  docs/x.md：壞了" not in out or len(calls) != 3:
            return f"受信任樹版有錯誤 → 退出碼 1、列出 ERR 行、其他兩次照跑（得到 {rc}、{out!r}）"
    check("run_all：有錯誤 → 退出碼 1", t_run_errors)

    def t_run_incomplete():
        for label, outputs, kw in [
            ("找不到摘要行", {"pr": (2, "ERROR: PyYAML 未安裝\n"), "trusted": (0, OK), "enforce": (0, OK)}, {}),
            ("退出碼與摘要不一致", {"pr": (0, BAD), "trusted": (0, OK), "enforce": (0, OK)}, {}),
            ("validate 崩潰", {"pr": (1, "Traceback (most recent call last):\n"), "trusted": (0, OK), "enforce": (0, OK)}, {}),
            ("副本建不起來", {"pr": (0, OK), "trusted": (0, OK), "enforce": (0, OK)}, {"fail_copy": True}),
            ("錯誤與無法執行同時出現", {"pr": (1, BAD), "trusted": (2, ""), "enforce": (0, OK)}, {}),
        ]:
            rc, out, calls, proj, tr = run_scenario(outputs, **kw)
            if rc != 2:
                return f"{label} → 退出碼 2（incomplete ≠ pass，優先於錯誤）（得到 {rc}、{out!r}）"
        for trusted, word in [("none", "沒有 scripts/validate.py"), ("missing", "不存在")]:
            rc, out, calls, proj, tr = run_scenario({"pr": (0, OK), "trusted": (0, OK), "enforce": (0, OK)}, trusted=trusted)
            if rc != 2 or calls or "--trusted" not in out or word not in out:
                return f"--trusted {word} → 退出碼 2、一次都不跑、訊息寫明「{word}」（得到 {rc}、{calls}、{out!r}）"
        rc, out, calls, proj, tr = run_scenario({"pr": (0, OK), "trusted": (0, OK), "enforce": (0, OK)}, trusted="old")
        if rc != 2 or [c[0] for c in calls] != ["pr", "enforce"] or "VIBESEC_PROJECT_ROOT" not in out:
            return (f"受信任樹的 validate 不認 VIBESEC_PROJECT_ROOT（會去驗受信任樹本身）→ 第 2 次記無法判定、不執行，"
                    f"退出碼 2（CI 是警告並略過；本機 fail closed）（得到 {rc}、{calls}、{out!r}）")
        rc, out, calls, proj, tr = run_scenario({"pr": (0, OK), "trusted": (0, OK), "enforce": (0, OK)},
                                                environ={"PATH": "/usr/bin", "VIBESEC_PROJECT_ROOT": "/elsewhere"})
        if [c[2] for c in calls] != [None, str(proj), None]:
            return f"呼叫端設了 VIBESEC_PROJECT_ROOT → 第 1、3 次拿掉、第 2 次改成受驗樹（得到 {calls}）"
    check("run_all：無法執行 → 退出碼 2", t_run_incomplete)

    # ---- enforce_copy：在小型暫存樹上真的執行（副本自己的 vibesec_policy.set_mode_line，和 CI 相同）
    def small_tree(d, yaml_text):
        """小型 git 樹：scripts/ 與 vibesec.yaml 已 commit；new.txt 未追蹤；ignored/ 與 _trusted/ 被 .gitignore 排除。"""
        src = pathlib.Path(d, "src")
        shutil.copytree(ROOT / "scripts", src / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
        (src / "vibesec.yaml").write_text(yaml_text, encoding="utf-8")
        (src / ".gitignore").write_text("ignored/\n__pycache__/\n", encoding="utf-8")
        git = lambda *a: subprocess.run(["git", "-C", str(src), *a], capture_output=True, text=True, check=True)
        git("init", "-q"); git("config", "user.email", "t@example.invalid"); git("config", "user.name", "t")
        git("config", "commit.gpgsign", "false"); git("add", "-A"); git("commit", "-qm", "init")
        (src / "new.txt").write_text("尚未 git add 的新檔\n", encoding="utf-8")
        (src / "ignored").mkdir(); (src / "ignored/big.bin").write_text("x")
        (src / "_trusted/scripts").mkdir(parents=True); (src / "_trusted/scripts/validate.py").write_text("")
        return src

    def t_copy_ok():
        with tempfile.TemporaryDirectory() as d:
            src = small_tree(d, "version: 1\nmode: shadow   # 註解\nrisk_tier: L3\n")
            with enforce_copy(src) as copy:
                copy = pathlib.Path(copy)
                text = (copy / "vibesec.yaml").read_text(encoding="utf-8")
                if copy == src or not (copy / ".git/HEAD").is_file() or not (copy / "scripts/validate.py").is_file() \
                        or not (copy / "new.txt").is_file():
                    return f"副本是另一棵樹：git 追蹤的檔案、未追蹤的新檔與 .git 都在（得到 {copy}）"
                if (copy / "ignored").exists() or (copy / "_trusted").exists():
                    return "副本不含 .gitignore 排除的檔案與 _trusted（和 CI checkout 出來的樹一致）"
                if [ln for ln in text.splitlines() if ln.startswith("mode:")] != ["mode: enforce"] or "risk_tier: L3" not in text:
                    return f"副本的最上層 mode 改成 enforce，其餘不動（得到 {text!r}）"
            if copy.exists() or "mode: shadow" not in (src / "vibesec.yaml").read_text(encoding="utf-8"):
                return f"離開後刪掉副本、原本的樹不動（副本存在：{copy.exists()}）"
    check("enforce_copy：保留 .git、改 mode、用完刪除", t_copy_ok)

    def t_copy_problem():
        with tempfile.TemporaryDirectory() as d:
            src = small_tree(d, "version: 1\nrisk_tier: L3\n")   # 沒有 mode 行：set_mode_line 找不到唯一的 mode
            before = set(pathlib.Path(tempfile.gettempdir()).glob("vibesec-enforce-*"))
            try:
                with enforce_copy(src):
                    return "沒有 mode 行 → CopyProblem"
            except CopyProblem:
                pass
            if set(pathlib.Path(tempfile.gettempdir()).glob("vibesec-enforce-*")) - before:
                return "建副本失敗也要刪掉副本"
    check("enforce_copy：改不了 mode → CopyProblem 並刪掉副本", t_copy_problem)

    # ---- main：只接受 --trusted；路徑不對時退出碼 2、不執行任何 validate
    import io

    def t_main():   # selftest 絕不執行真的 validate（validate 會跑所有 selftest → 遞迴）：runner 一被呼叫就失敗
        calls = []
        def refuse(cmd, *, cwd, env):
            calls.append(cmd)
            raise RuntimeError("selftest 不得執行 validate")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                main([], runner=refuse, environ={}); return "沒有 --trusted → argparse 以退出碼 2 結束"
            except SystemExit as e:
                if e.code != 2:
                    return f"沒有 --trusted → 退出碼 2（得到 {e.code}）"
            rc = main(["--trusted", "/nonexistent/vibesec-trusted"], runner=refuse, environ={})
        if rc != 2 or "--trusted" not in out.getvalue() or calls:
            return f"--trusted 不存在 → 退出碼 2、訊息提到 --trusted、不執行 validate（得到 {rc}、{calls}、{out.getvalue()!r}）"
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = main(["--trusted", str(ROOT)], runner=refuse, environ={RUNNING: "1"})
        if rc != 2 or calls:
            return f"已在 ci_validate 執行的 validate 裡 → 退出碼 2、不再執行 validate（防遞迴）（得到 {rc}、{calls}）"
        seen = []
        rc, _ = run_all(ROOT, ROOT, runner=lambda cmd, *, cwd, env: seen.append(env.get(RUNNING)) or (0, "通過 1 項；警告 0；錯誤 0\n"),
                        make_copy=copier())
        if seen != ["1", "1", "1"]:
            return f"三次執行都帶 {RUNNING}=1，讓巢狀的 ci_validate 停下來（得到 {seen}）"
    check("main：--trusted 必填、路徑不對時退出碼 2", t_main)
    return fails


def main(argv=None, *, runner=None, make_copy=None, environ=None) -> int:
    """runner、make_copy、environ 只給 selftest 注入（selftest 絕不執行真的 validate）。"""
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["selftest"]:
        fails = selftest()
        print("\n".join(f"FAIL {x}" for x in fails) or "ci_validate selftest ok")
        return 1 if fails else 0
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--trusted", required=True, help="受信任樹（通常是 workflow 第 0 步的 main worktree，例如 /tmp/wt-main）")
    a = ap.parse_args(argv)
    if (os.environ if environ is None else environ).get(RUNNING):
        print(f"已在 ci_validate 執行的 validate 裡（{RUNNING}=1），不再巢狀執行（incomplete ≠ pass）")
        return 2
    rc, lines = run_all(ROOT, pathlib.Path(a.trusted), runner=runner or subprocess_runner, make_copy=make_copy or enforce_copy)
    print("\n".join(lines))
    return rc


def subprocess_runner(cmd, *, cwd, env) -> tuple[int, str]:
    """實際執行 validate（每次最多 TIMEOUT 秒）；逾時或無法執行 → 回傳沒有摘要行的輸出，由 run_all 記為無法判定。"""
    try:
        r = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True, timeout=TIMEOUT)
    except (OSError, subprocess.TimeoutExpired) as e:
        return 2, f"無法執行 validate：{type(e).__name__}: {e}"
    return r.returncode, (r.stdout or "") + (r.stderr or "")


if __name__ == "__main__":
    sys.exit(main())
