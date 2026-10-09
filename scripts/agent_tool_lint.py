"""以 Python 語法樹檢查工具註冊；規則字串與說明文字不是工具暴露。"""
import ast
import re

DANGEROUS = re.compile(r'(delete_user|execute_sql|drop_table)', re.I)
REGISTRARS = {'tool', 'function_tool', 'register_tool', 'add_tool', 'from_function'}


def name(node):
    if isinstance(node, ast.Name): return node.id
    if isinstance(node, ast.Attribute): return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str): return node.value
    return ''


def tool_collection(node):
    return bool(re.search(r'(^|_)tools?($|_)|^functions$', name(node), re.I))


def exposures(source):
    # 解析失敗交由呼叫端標記未完成，不把未知語法當作安全。
    tree = ast.parse(source)
    found, bindings = set(), {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign)) and node.value is not None:
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            for target in targets:
                if isinstance(target, ast.Name): bindings.setdefault(target.id, []).append(node.value)
    def inspect(value, seen=frozenset()):
        for child in ast.walk(value):
            if DANGEROUS.fullmatch(name(child)):
                found.add((child.lineno, name(child)))
            elif isinstance(child, ast.Name) and child.id not in seen:
                for bound in bindings.get(child.id, []): inspect(bound, seen | {child.id})
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decorated = any(name(d.func if isinstance(d, ast.Call) else d).lower() in REGISTRARS for d in node.decorator_list)
            if decorated and DANGEROUS.fullmatch(node.name): found.add((node.lineno, node.name))
        elif isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            if node.value is not None and any(tool_collection(t) for t in targets): inspect(node.value)
        elif isinstance(node, ast.Call):
            for keyword in node.keywords:
                if keyword.arg in ('tools', 'functions'): inspect(keyword.value)
            registrar = name(node.func).lower() in REGISTRARS
            extending = (isinstance(node.func, ast.Attribute) and node.func.attr in ('append', 'extend', 'register')
                         and tool_collection(node.func.value))
            if registrar or extending:
                for argument in node.args: inspect(argument)
                for keyword in node.keywords:
                    if keyword.arg in ('name', 'func', 'function'): inspect(keyword.value)
    return sorted(found)
