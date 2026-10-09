#!/usr/bin/env python3
"""下載 CISA 官方 KEV；官網不可用時改取 CISA 維護的官方 GitHub 鏡像。"""
import argparse
import json
import pathlib
import urllib.request

SOURCES = ('https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
           'https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json')


def fetch(path):
    errors = []
    for url in SOURCES:
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={'User-Agent': 'vibesec-kev'}), timeout=60) as r:
                raw = r.read()
            data = json.loads(raw)
            if not isinstance(data.get('vulnerabilities'), list) or not data['vulnerabilities'] or not data.get('dateReleased'):
                raise ValueError('KEV 結構不完整')
            path = pathlib.Path(path); path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix('.download'); tmp.write_bytes(raw); tmp.replace(path)
            return url
        except (OSError, ValueError) as e: errors.append(f'{url}: {type(e).__name__}')
    raise OSError('；'.join(errors))

if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__); ap.add_argument('out'); a = ap.parse_args()
    print(fetch(a.out))
