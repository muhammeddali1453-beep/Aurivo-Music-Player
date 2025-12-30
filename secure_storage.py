import io
import json
import os
import pickle
import tempfile
from typing import Any, Optional


def contains_path_traversal(path_str: str) -> bool:
    if not isinstance(path_str, str):
        return True
    s = path_str.replace("\\", "/")
    parts = [p for p in s.split("/") if p not in ("", ".")]
    return any(p == ".." for p in parts)


def atomic_write_text(path: str, text: str, encoding: str = "utf-8") -> None:
    directory = os.path.dirname(os.path.abspath(path)) or "."
    os.makedirs(directory, exist_ok=True)

    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except Exception:
            pass


def atomic_write_json(path: str, obj: Any) -> None:
    atomic_write_text(path, json.dumps(obj, ensure_ascii=False, indent=2))


def load_json_file(path: str) -> Optional[Any]:
    try:
        if not os.path.exists(path):
            return None
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


class _RestrictedUnpickler(pickle.Unpickler):
    """Yalnızca temel builtins tiplerine izin veren güvenli (kısıtlı) unpickler."""

    _ALLOWED = {
        "builtins": {
            "dict",
            "list",
            "set",
            "tuple",
            "str",
            "bytes",
            "int",
            "float",
            "bool",
        }
    }

    def find_class(self, module: str, name: str):
        allowed = self._ALLOWED.get(module)
        if allowed and name in allowed:
            return getattr(__import__(module, fromlist=[name]), name)
        raise pickle.UnpicklingError("global '%s.%s' yasak" % (module, name))


def safe_load_pickle_simple(path: str) -> Any:
    """Sadece basit tiplerden oluşan pickle'ı güvenli biçimde yüklemeyi dener."""

    # Symlink veya dizin gibi riskli durumları fail-closed
    st = os.lstat(path)
    if not os.path.isfile(path) or os.path.islink(path):
        raise ValueError("pickle path güvenli değil")

    with open(path, "rb") as f:
        data = f.read()

    return _RestrictedUnpickler(io.BytesIO(data)).load()


def migrate_pickle_config_to_json(pickle_path: str, json_path: str) -> bool:
    """Eski config pickle -> JSON migrate. Başarılıysa True."""
    try:
        obj = safe_load_pickle_simple(pickle_path)
        if not isinstance(obj, dict):
            return False
        atomic_write_json(json_path, obj)
        return True
    except Exception:
        return False


def migrate_pickle_playlist_to_json(pickle_path: str, json_path: str) -> bool:
    """Eski playlist pickle -> {paths,current_index} JSON migrate. Başarılıysa True."""
    try:
        obj = safe_load_pickle_simple(pickle_path)
        # Beklenen eski formatlar: (paths, current_index) veya {'paths':..., 'current_index':...} veya sadece paths listesi
        if isinstance(obj, dict):
            paths = obj.get("paths", [])
            current_index = obj.get("current_index", -1)
        elif isinstance(obj, (list, tuple)):
            if len(obj) == 2 and isinstance(obj[0], (list, tuple)):
                paths = list(obj[0])
                current_index = int(obj[1])
            else:
                paths = list(obj)
                current_index = -1
        else:
            return False

        if not isinstance(paths, list):
            paths = list(paths)

        atomic_write_json(json_path, {"paths": paths, "current_index": int(current_index)})
        return True
    except Exception:
        return False
