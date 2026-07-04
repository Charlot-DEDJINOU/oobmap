import copy
import re


def _json_path_parts(path: str) -> list[str | int]:
    parts: list[str | int] = []
    for segment in re.split(r'\.(?![^\[]*\])', path):
        if not segment:
            continue
        base = re.sub(r'\[\d+\].*', '', segment)
        parts.append(base)
        for idx in re.findall(r'\[(\d+)\]', segment):
            parts.append(int(idx))
    return parts


def _json_get(obj: object, path: str) -> object:
    for key in _json_path_parts(path):
        obj = obj[key]  # type: ignore[index]
    return obj


def _json_set(obj: object, path: str, value: str) -> object:
    root = copy.deepcopy(obj)
    parts = _json_path_parts(path)
    node: object = root
    for key in parts[:-1]:
        node = node[key]  # type: ignore[index]
    node[parts[-1]] = value  # type: ignore[index]
    return root


def _json_leaf_paths(obj: object, prefix: str = ""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from _json_leaf_paths(v, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from _json_leaf_paths(v, f"{prefix}[{i}]")
    elif isinstance(obj, str):
        yield prefix, obj
