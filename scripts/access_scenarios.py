"""執行受測專案宣告的跨帳號／跨角色情境；只呼叫授權來源。"""
import hashlib
import json
import re
import urllib.parse


def run(client, config, tokens, env):
    findings, states = [], []
    resources = config.get('resources') or []
    auth = config.get('auth') or {'scheme': 'bearer'}
    def request(spec, actor, rid=None):
        path = spec['path']
        if rid is not None: path = path.replace('{id}', urllib.parse.quote(str(rid), safe=''))
        token = tokens.get(actor)
        headers = {}
        scheme = auth.get('scheme', 'bearer')
        if token and scheme == 'cookie': headers['Cookie'] = f"{auth['cookie_name']}={token}"; token = None
        elif token and scheme == 'header': headers[auth.get('header', 'Authorization')] = token; token = None
        elif scheme != 'bearer' and scheme not in ('cookie', 'header'): raise ValueError('不支援的認證方式')
        return client.request(path, spec.get('method', 'GET'), token, spec.get('body'), headers)
    def check(label, spec, expected, rid=None):
        for actor, allowed in expected.items():
            if actor != 'ANON' and not tokens.get(actor):
                states.append((label, 'untested', f'{actor} 缺少權杖')); continue
            status, body = request(spec, actor, rid)
            if status in allowed:
                states.append((label, 'pass', None))
            elif status is not None and 200 <= status < 300 and actor in ('B', 'ANON'):
                rule = 'vibesec.g5.missing-session-check' if actor == 'ANON' else 'vibesec.g5.bola-cross-account'
                findings.append((rule, f'{label}：{actor} 非預期取得 HTTP {status}；回應指紋 {hashlib.sha256(body.encode()).hexdigest()[:16]}'))
                states.append((label, 'fail', None))
            else:
                states.append((label, 'untested', f'{actor} 回應 {status}，未取得宣告的驗證證據'))
    for resource in resources:
        label = resource['name']
        if not tokens.get('A') or not tokens.get('B') or tokens['A'] == tokens['B']:
            states.append((label, 'untested', '需要兩個不同帳號的權杖')); continue
        if resource.get('id_from') == 'create':
            spec = resource['create_request']
            status, body = request(spec, 'A')
            try:
                if status is None or not 200 <= status < 300: raise ValueError('建立資源未成功')
                rid = json.loads(body)
                for key in spec.get('id_json_path', '$.id').removeprefix('$.').split('.'): rid = rid[key]
                if not isinstance(rid, (str, int)): raise ValueError('id 不是純量')
            except (ValueError, KeyError, TypeError):
                states.append((label, 'untested', '無法以 A 建立測試資源')); continue
        else:
            rid = env.get(resource.get('seed_id_env', ''))
            if not rid:
                states.append((label, 'untested', '缺少測試資源 id')); continue
        # 先驗證非擁有者，避免 A 的 DELETE 先刪掉資源而讓 B 的 404 空洞通過。
        for spec in resource.get('requests') or []:
            expected = resource.get('expect') or {}
            check(label, spec, {k: v for k, v in expected.items() if k != 'A'}, rid)
        read = next((r for r in resource.get('requests', []) if r.get('method', 'GET') == 'GET'), None)
        if read: check(label, read, {'A': resource.get('expect', {}).get('A', [200])}, rid)
    for item in config.get('list_isolation') or []:
        status, body = request(item, 'B') if tokens.get('B') else (None, '')
        if status == 200 and item.get('marker'):
            hit = item['marker'] in body
            states.append((item['path'], 'fail' if hit else 'pass', None))
            if hit: findings.append(('vibesec.g5.bola-cross-account', f"清單 {item['path']} 包含 A 的測試標記"))
        else: states.append((item['path'], 'untested', '清單隔離未取得有效回應'))
    for spec in config.get('function_level') or []:
        rid = env.get(spec.get('id_from_env', ''))
        if '{id}' in spec['path'] and rid is None:
            states.append((spec['path'], 'untested', '缺少功能權限測試 id')); continue
        check(spec['path'], spec, spec.get('expect') or {}, rid)
    state = 'fail' if any(s[1] == 'fail' for s in states) else 'untested' if not states or any(s[1] == 'untested' for s in states) else 'pass'
    return findings, state, '；'.join(f'{label}: {why}' for label, st, why in states if why)
