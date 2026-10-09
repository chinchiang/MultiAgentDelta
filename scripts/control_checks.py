#!/usr/bin/env python3
"""檢查宣告的 HTTP 標頭與 Agent 工具設定；供 harness 與設定案例共用。"""
import argparse
import json
import pathlib
import re
import yaml


def check(config):
    if not isinstance(config, dict): raise ValueError("設定必須是物件")
    if "headers" in config and (not isinstance(config["headers"], dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in config["headers"].items())): raise ValueError("headers 必須是字串對照")
    if not isinstance(config.get("tools", []), list) or not all(isinstance(t, str) or isinstance(t, dict) and isinstance(t.get("name"), str) for t in config.get("tools", [])): raise ValueError("tools 必須是名稱或具 name 的物件清單")
    found = []
    if 'headers' in config:
        headers = {k.lower(): v for k, v in config['headers'].items()}
        if 'text/html' in headers.get('content-type', '') and not headers.get('content-security-policy', '').strip():
            found.append('vibesec.g3.missing-csp')
    tools = config.get('tools', [])
    hitl = config.get('require_confirmation') is True or config.get('human_in_the_loop') is True
    for tool in tools:
        name = tool if isinstance(tool, str) else tool.get('name', '')
        approved = hitl or (isinstance(tool, dict) and tool.get('require_confirmation') is True)
        if re.search(r'delete|drop|transfer|refund|payment|execute_sql|send_email', name, re.I) and not approved:
            found.append('vibesec.g4.missing-hitl')
    return sorted(set(found))


def main():
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('config'); a = ap.parse_args()
    try:
        config = yaml.safe_load(pathlib.Path(a.config).read_text())
        if not isinstance(config, dict): raise ValueError('設定必須是物件')
        print(json.dumps({'rules': check(config)}, ensure_ascii=False))
    except (OSError, ValueError, TypeError, yaml.YAMLError) as e:
        print(json.dumps({'status': 'incomplete', 'reason': str(e)}, ensure_ascii=False)); return 2
    return 0

if __name__ == '__main__': raise SystemExit(main())
