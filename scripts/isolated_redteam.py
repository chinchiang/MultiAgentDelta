#!/usr/bin/env python3
"""隔離 G6 第三方工具與憑證。 / Isolate G6 third-party tools from credentials."""
import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import threading
import yaml
from runtime_broker import Broker, Server, handler

ROOT = Path(__file__).resolve().parents[1]


def provider_config(env, root=ROOT):
    providers = yaml.safe_load((root / 'config/providers.yaml').read_text())['providers']
    for name, variable in [('anthropic', 'ANTHROPIC_API_KEY'), ('openai', 'OPENAI_API_KEY')]:
        if env.get(variable):
            config = providers[name + '-cloud']
            if not config.get('enabled') or 'internal' not in config.get('allowed_data_classes', []):
                raise ValueError('Provider not allowed for internal data / 模型不得接收內部資料')
            expected = 'https://api.anthropic.com' if name == 'anthropic' else 'https://api.openai.com/v1'
            if str(config.get('base_url', '')).rstrip('/') != expected or config.get('api_key_env') != variable:
                raise ValueError('Broker does not support this endpoint or key binding / 轉接器不支援此端點或金鑰設定')
            if not isinstance(config.get('model'), str) or not config['model'].strip():
                raise ValueError('Missing model identifier / 缺少模型識別碼')
            return name, config['model'], env[variable]
    raise ValueError('No generation key configured / 未設定生成層金鑰')


def docker_command(image, inputs, output, broker, mode):
    command = ['docker', 'run', '--rm', '--log-driver', 'none', '--name', 'vibesec-' + inputs.parent.name, '--network', 'none', '--read-only', '--cap-drop', 'ALL',
               '--security-opt', 'no-new-privileges', '--user', '65532:65532', '--pids-limit', '256',
               '--memory', '4g', '--cpus', '2', '--ulimit', 'fsize=67108864:67108864',
               '--tmpfs', '/tmp:rw,nosuid,nodev,size=512m', '--workdir', '/tmp',
               '--mount', f'type=bind,src={inputs},dst=/input,readonly',
               '--mount', f'type=bind,src={output},dst=/output',
               '--mount', f'type=bind,src={broker},dst=/broker,readonly']
    # 覆寫 Docker 用戶端的預設代理注入；主機的代理與 CA 保持不變。 / Override container proxy defaults only.
    variables = {'HTTP_PROXY':'', 'HTTPS_PROXY':'', 'ALL_PROXY':'', 'NO_PROXY':'',
                 'http_proxy':'', 'https_proxy':'', 'all_proxy':'', 'no_proxy':'',
                 'HOME':'/tmp', 'XDG_DATA_HOME':'/tmp/data', 'XDG_CONFIG_HOME':'/tmp/config',
                 'VIBESEC_TARGET_URL':'http://127.0.0.1:8080/target',
                 'PROMPTFOO_DISABLE_TELEMETRY':'1', 'PROMPTFOO_DISABLE_REMOTE_GENERATION':'true',
                 'OPENAI_API_KEY':'broker-placeholder', 'ANTHROPIC_API_KEY':'broker-placeholder',
                 'OPENAI_BASE_URL':'http://127.0.0.1:8080/provider/v1',
                 'ANTHROPIC_BASE_URL':'http://127.0.0.1:8080/provider'}
    for key, value in variables.items(): command += ['--env', f'{key}={value}']
    command += ['--entrypoint', 'python', image, '/input/runtime_bridge.py']
    if mode == 'garak':
        command += ['garak', '--config', '/input/config.yaml', '--report_prefix', '/output/g6-garak']
    else:
        command += ['promptfoo', *(['redteam', 'run'] if mode == 'redteam' else ['eval']),
                    '-c', '/input/config.yaml', '--no-cache', '--output', '/output/result.json']
    return command


def run(mode, image, target, output, env=None, timeout=1800):
    env = os.environ if env is None else env
    output.mkdir(parents=True, exist_ok=True)
    log_name = {'eval':'_promptfoo.log','redteam':'_promptfoo-redteam.log','garak':'_garak.log'}[mode]
    if (output/log_name).exists() or (output/log_name).is_symlink(): (output/log_name).unlink()
    # 先清除上次的同類結果，避免工具啟動失敗卻採用舊報告。 / Never reuse stale output after a startup failure.
    names = ['g6-promptfoo.json'] if mode == 'eval' else ['g6-promptfoo-redteam.json'] if mode == 'redteam' else []
    stale = [output/name for name in names] if names else list(output.glob('g6-garak*.report.jsonl'))
    for path in stale:
        if path.exists() or path.is_symlink(): path.unlink()
    provider, model, key = provider_config(env) if mode == 'redteam' else (None, None, None)
    # garak 的完整固定探針集包含數萬次本機靶場呼叫；生成層仍保持較低上限。
    # The complete garak suite can make tens of thousands of target calls; generation retains a lower cap.
    broker = Broker(target, provider, model, key, max_requests=50000 if mode == 'garak' else 1000)
    # 解析為本機不可變 image ID，不讓執行步驟下載或改變工具。 / Resolve a local immutable ID; no runtime pull.
    image_id = subprocess.check_output(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], text=True).strip()
    if not image_id.startswith('sha256:') or len(image_id) != 71:
        raise ValueError('Invalid local image ID / 無效的本機映像識別碼')
    with tempfile.TemporaryDirectory(prefix='vibesec-isolated-') as directory:
        temp = Path(directory); temp.chmod(0o755)
        inputs, results, sockets = (temp / name for name in ('input', 'output', 'broker'))
        for path in (inputs, results, sockets):
            path.mkdir(mode=0o755); path.chmod(0o755)
        results.chmod(0o777)
        shutil.copyfile(ROOT/'scripts/runtime_bridge.py', inputs/'runtime_bridge.py')
        config_path = ROOT / ('config/garak/vibesec.probes.yaml' if mode == 'garak' else
                             'config/promptfoo/promptfooconfig.yaml' if mode == 'redteam' else 'config/promptfoo/tests.yaml')
        config = yaml.safe_load(config_path.read_text())
        if mode == 'garak':
            config['plugins']['generators']['rest']['RestGenerator']['uri'] = 'http://127.0.0.1:8080/target/chat'
        elif mode == 'redteam':
            pid = f'{provider}:messages:{model}' if provider == 'anthropic' else f'openai:chat:{model}'
            selected = {'id':pid, 'config':{'apiBaseUrl':'http://127.0.0.1:8080/provider' + ('/v1' if provider == 'openai' else ''),
                                           'max_tokens':4096, 'temperature':0}}
            config.setdefault('redteam', {})['provider'] = selected
            config.setdefault('defaultTest', {}).setdefault('options', {})['provider'] = selected
        (inputs/'config.yaml').write_text(yaml.safe_dump(config, allow_unicode=True))
        for path in inputs.iterdir(): path.chmod(0o644)
        socket_path = sockets/'http.sock'
        server = Server(str(socket_path), handler(broker)); socket_path.chmod(0o666)
        thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
        output.mkdir(parents=True, exist_ok=True)
        try:
            # 日誌位於主機，容器無法替換為 symlink。 / Host-owned log cannot be replaced by a container symlink.
            with (output/log_name).open('wb') as log:
                process = subprocess.Popen(docker_command(image_id, inputs, results, sockets, mode),
                                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                def drain():
                    remaining = 4*1024*1024
                    while chunk := process.stdout.read(65536):
                        if remaining:
                            log.write(chunk[:remaining]); remaining = max(0, remaining-len(chunk))
                    process.stdout.close()
                reader = threading.Thread(target=drain, daemon=True); reader.start()
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
                    code = 124
                finally:
                    subprocess.run(['docker', 'rm', '--force', 'vibesec-' + inputs.parent.name],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
                    reader.join(timeout=30)
            if broker.budget_exhausted: code = 2
            (output/f'g6-runtime-{mode}.json').write_text(json.dumps({
                'exit_code':code, 'budget_exhausted':broker.budget_exhausted,
                'remaining_requests':broker.remaining, 'network':'none',
                'note':'異常退出或用量上限不算通過。 / Abnormal exit or exhausted budget is not a pass.'},indent=2))
            for path in sorted(results.iterdir()):
                if path.name != 'result.json' and not (path.name.startswith('g6-garak') and path.name.endswith('.report.jsonl')):
                    continue
                info = path.lstat()
                if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_size > 64*1024*1024:
                    raise ValueError('Unsafe tool output / 工具輸出不安全')
                destination = output / (('g6-promptfoo-redteam.json' if mode == 'redteam' else 'g6-promptfoo.json')
                                        if path.name == 'result.json' else path.name)
                if code not in ((0,) if mode == 'garak' else (0, 100)):
                    destination = destination.with_name('partial-' + destination.name)
                shutil.copyfile(path, destination)
        finally:
            server.shutdown(); server.server_close(); thread.join()
        return code


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=['eval','redteam','garak'])
    parser.add_argument('--image', required=True)
    parser.add_argument('--output', type=Path, default=Path('reports'))
    args = parser.parse_args()
    try:
        return run(args.mode, args.image, os.environ['VIBESEC_TARGET_URL'], args.output)
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f'隔離工具未完成 / Isolated tool incomplete: {type(error).__name__}')
        return 2


if __name__ == '__main__': raise SystemExit(main())
