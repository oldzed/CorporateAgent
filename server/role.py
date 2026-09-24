import json
import re

_compiled = {}   # {role_name: [(pattern_str, compiled_re), ...]}
_EMPTY = []


def load_roles(path="role.json"):
    """加载 role.json，预编译正则。启动时调一次。"""
    global _compiled
    _compiled = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"[role] 未找到 {path}，所有请求放行")
        return
    except Exception as e:
        print(f"[role] 加载 {path} 失败: {e}，所有请求放行")
        return

    for role_name, cfg in data.get("roles", {}).items():
        pats = []
        for p in cfg.get("blacklist", []):
            try:
                pats.append((p, re.compile(p, re.IGNORECASE)))
            except re.error as e:
                print(f"[role] 无效正则 [{role_name}] {p!r}: {e}")
        _compiled[role_name] = pats

    print(f"[role] 已加载 {len(_compiled)} 个规则组: "
          f"{', '.join(_compiled.keys()) or '(空)'}")


def check(role_name, host):
    """
    返回 (action, pattern)
    action: "allow" / "block"
    pattern: 命中的正则字符串，未命中为 None
    """
    if not host:
        return "allow", None
    for pattern_str, creg in _compiled.get(role_name, _EMPTY):
        if creg.search(host):
            return "block", pattern_str
    return "allow", None