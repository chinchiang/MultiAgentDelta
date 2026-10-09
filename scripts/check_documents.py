#!/usr/bin/env python3
"""檢查雙語文件、連結與提示版本；不判定翻譯正確性。
Check bilingual structure, local links, paired updates, and prompt versions; not translation accuracy.
"""
from __future__ import annotations
import argparse
import datetime
import html
import pathlib
import re
import subprocess
import unicodedata
from urllib.parse import unquote, urlsplit

ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKERS = ('<a id="zh-tw"></a>', '<a id="english"></a>')
VERSION = re.compile(r'^prompt_version:\s*([\w-]+)@(\d{4}-\d{2}-\d{2})\.(\d+)\s*$', re.M)


def git(root, *args):
    result = subprocess.run(['git', '-C', str(root), *args], capture_output=True, text=True)
    if result.returncode:
        raise ValueError('無法讀取 Git 資料 / Cannot read Git data: ' + ' '.join(args[:2]))
    return result.stdout


def prose(text):
    """排除共用程式碼與前置資料。 / Exclude shared code and frontmatter."""
    text = re.sub(r'\A---\n.*?\n---\n', '', text, flags=re.S)
    lines, fence = [], None
    for line in text.splitlines():
        m = re.match(r'^\s{0,3}(`{3,}|~{3,})', line)
        if m:
            if fence is None:
                fence = m[1]
            elif m[1][0] == fence[0] and len(m[1]) >= len(fence):
                fence = None
            continue
        if fence is None:
            lines.append(line)
    return re.sub(r'<!--.*?-->', '', '\n'.join(lines), flags=re.S)


def sections(text):
    body = prose(text)
    if any(body.count(marker) != 1 for marker in MARKERS):
        raise ValueError('每種語言須有一個錨點 / Each language needs exactly one anchor')
    before, rest = body.split(MARKERS[0])
    if MARKERS[1] in before:
        raise ValueError('語言順序須為中文、英文 / Chinese must precede English')
    zh, en = rest.split(MARKERS[1])
    def content(section):
        return '\n'.join(line for line in section.splitlines()
                         if not re.match(r'^\s*(?:#{1,6}\s|<[^>]+>\s*$|[-=]{3,}\s*$)', line))
    if not re.search(r'[\u4e00-\u9fff]', content(zh)) or len(re.findall(r'[A-Za-z]{2,}', content(en))) < 3:
        raise ValueError('雙語正文不可空白 / Both language sections need substantive text')
    if not all(f'](#{anchor})' in before for anchor in ('zh-tw', 'english')):
        raise ValueError('缺少雙語導覽 / Missing bilingual navigation')
    return tuple(re.sub(r'\s+', ' ', s).strip(' -') for s in (zh, en))


def anchors(text):
    body = prose(text)
    result = set(re.findall(r'\bid=["\']([^"\']+)["\']', body))
    counts = {}
    lines = body.splitlines()
    for i, line in enumerate(lines):
        heading = re.match(r'^ {0,3}#{1,6}\s+(.+?)(?:\s+#+)?\s*$', line)
        value = heading[1] if heading else None
        if value is None and i + 1 < len(lines) and re.match(r'^ {0,3}(?:=+|-+)\s*$', lines[i+1]) and line.strip():
            value = line.strip()
        if value is None:
            continue
        value = re.sub(r'<[^>]+>', '', value)
        value = re.sub(r'\[([^]]+)\]\([^)]*\)', r'\1', value)
        value = html.unescape(value).lower().replace(' ', '-')
        slug = ''.join(c for c in value if c in '-_' or unicodedata.category(c)[0] in 'LN')
        n = counts.get(slug, 0)
        counts[slug] = n + 1
        result.add(slug + (f'-{n}' if n else ''))
    return result


def links(text):
    body = prose(text)
    # 行內程式碼不是連結。 / Inline code is not a link.
    body = re.sub(r'(`+).*?\1', '', body)
    pattern = r'!?\[[^]\n]*\]\(\s*(?:<([^>]+)>|([^\s)]+))(?:\s+["\'][^\n]*?["\'])?\s*\)'
    targets = [a or b for a, b in re.findall(pattern, body)]
    definitions = dict((label.strip().lower(), a or b) for label, a, b in re.findall(
        r'^ {0,3}\[([^]]+)\]:\s*(?:<([^>]+)>|(\S+))', body, re.M))
    targets.extend(definitions.values())
    missing = []
    for label, ref in re.findall(r'!?\[([^]\n]+)\]\[([^]\n]*)\]', body):
        if (ref or label).strip().lower() not in definitions:
            missing.append(ref or label)
    return targets, missing


def check(root=ROOT, base=None):
    root = pathlib.Path(root).resolve()
    errors = []
    files = git(root, 'ls-files', '-z', '--', '*.md').split('\0')
    files = [f for f in files if f and (root/f).exists()]
    if not files:
        return ['找不到追蹤中的 Markdown / No tracked Markdown files'], 0
    old_files = set(git(root, 'ls-tree', '-r', '--name-only', base).splitlines()) if base else set()
    for name in files:
        path = root/name
        text = path.read_text(encoding='utf-8')
        try:
            current = sections(text)
        except ValueError as e:
            errors.append(f'{name}: {e}')
            current = None
        targets, missing = links(text)
        for label in missing:
            errors.append(f'{name}: 連結定義缺漏 / Missing link definition: {label}')
        for target in targets:
            url = urlsplit(target)
            if url.scheme or url.netloc:
                continue
            dest = (root/unquote(url.path).lstrip('/') if url.path.startswith('/') else path.parent/unquote(url.path)) if url.path else path
            dest = dest.resolve()
            if not dest.is_relative_to(root) or not dest.exists():
                errors.append(f'{name}: 本機連結不存在或超出倉庫 / Missing or out-of-repository local link: {target}')
            elif url.fragment and dest.suffix.lower() == '.md' and unquote(url.fragment) not in anchors(dest.read_text(encoding='utf-8')):
                errors.append(f'{name}: 錨點不存在 / Missing anchor: {target}')
        prompt = name.startswith('config/harness/')
        version = VERSION.search(text)
        if version:
            try:
                datetime.date.fromisoformat(version[2])
            except ValueError:
                version = None
        if prompt and not version:
            errors.append(f'{name}: 缺少有效提示版本 / Missing valid prompt_version')
        if base and name in old_files:
            old = git(root, 'show', f'{base}:{name}')
            try:
                previous = sections(old)
            except ValueError:
                previous = None  # 首次雙語轉換仍須通過現行格式檢查。 / Initial translation must satisfy current structure.
            if current and previous and ((current[0] != previous[0]) != (current[1] != previous[1])):
                errors.append(f'{name}: 只更新單一語言，請同步翻譯 / Only one language changed; update both translations')
            if prompt and old != text:
                old_version = VERSION.search(old)
                if old_version and (not version or version[1] != old_version[1] or (version[2], int(version[3])) <= (old_version[2], int(old_version[3]))):
                    errors.append(f'{name}: 提示已變更，版本必須遞增 / Changed prompt requires an increased version')
    return errors, len(files)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', help='比較用基底提交 / Base commit for paired updates and prompt versions')
    args = parser.parse_args()
    try:
        errors, count = check(base=args.base)
    except (ValueError, OSError, UnicodeError) as e:
        print(f'文件檢查未完成 / Document check incomplete: {e}')
        return 2
    for error in errors:
        print(error)
    print(f'文件 {count} 份；錯誤 {len(errors)} / Documents: {count}; errors: {len(errors)}')
    return 1 if errors else 0


if __name__ == '__main__':
    raise SystemExit(main())
