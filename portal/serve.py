#!/usr/bin/env python3
# 入口页静态文件 + 工具集源码浏览。只读，不写仓库。
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse
import json

PORT = 8090
HOST = "127.0.0.1"
ROOT = Path(__file__).resolve().parent
MODULES_ROOT = ROOT.parent / "modules"

MODULES = {
    "sgboost": MODULES_ROOT / "SGBoost-main",
    "kangaroo": MODULES_ROOT / "kangaroo",
    "byte": MODULES_ROOT / "byte",
    "ttsdc": MODULES_ROOT / "TTSDC",
    "seccom-tee": MODULES_ROOT / "seccom-tee",
    "pqcp": MODULES_ROOT / "PQCP-main",
}

SKIP_DIRS = {
    ".git",
    "__pycache__",
    "node_modules",
    "cmakefiles",
    ".venv",
    "venv",
    "dist",
    ".idea",
    ".vscode",
    "build",
}
SKIP_SUFFIX = {
    ".pyc",
    ".o",
    ".obj",
    ".exe",
    ".dll",
    ".so",
    ".a",
    ".lib",
    ".bin",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".webp",
    ".ico",
    ".pdf",
    ".zip",
    ".jar",
    ".class",
    ".out",
}
MAX_BYTES = 1024 * 1024


def safe_root(mod_id):
    root = MODULES.get(mod_id)
    if root is None or not root.exists():
        return None
    return root.resolve()


def safe_path(mod_id, rel):
    root = safe_root(mod_id)
    if root is None:
        return None
    rel = (rel or "").replace("\\", "/").lstrip("/")
    if ".." in Path(rel).parts:
        return None
    target = (root / rel).resolve() if rel else root
    try:
        target.relative_to(root)
    except ValueError:
        return None
    return target


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def log_message(self, fmt, *args):
        sys_stderr = __import__("sys").stderr
        sys_stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/list":
            self._list(parsed)
            return
        if parsed.path == "/api/file":
            self._file(parsed)
            return
        return super().do_GET()

    def _qs(self, parsed):
        q = parse_qs(parsed.query)
        mod_id = (q.get("id") or [""])[0]
        rel = unquote((q.get("path") or [""])[0])
        return mod_id, rel

    def _json(self, code, payload):
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, code, text, mime="text/plain; charset=utf-8"):
        body = text.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", mime)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _list(self, parsed):
        mod_id, rel = self._qs(parsed)
        target = safe_path(mod_id, rel)
        if target is None or not target.is_dir():
            self._json(404, {"error": "not found"})
            return
        dirs, files = [], []
        try:
            entries = sorted(target.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))
        except OSError:
            self._json(500, {"error": "read error"})
            return
        for item in entries:
            name = item.name
            if name.startswith("."):
                continue
            if item.is_dir():
                if name.lower() in SKIP_DIRS:
                    continue
                dirs.append(name)
            else:
                if item.suffix.lower() in SKIP_SUFFIX:
                    continue
                files.append(name)
        self._json(200, {"dirs": dirs, "files": files})

    def _file(self, parsed):
        mod_id, rel = self._qs(parsed)
        target = safe_path(mod_id, rel)
        if target is None or not target.is_file():
            self._text(404, "文件不存在")
            return
        if target.suffix.lower() in SKIP_SUFFIX:
            self._text(415, "二进制文件，未打开")
            return
        data = target.read_bytes()
        truncated = False
        if len(data) > MAX_BYTES:
            data = data[:MAX_BYTES]
            truncated = True
        text = decode_bytes(data)
        if truncated:
            text += "\n\n… 文件超过 1MB，只显示开头。"
        self._text(200, text, "text/plain; charset=utf-8")


def decode_bytes(data):
    for enc in ("utf-8-sig", "utf-8", "gbk", "utf-16"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", "replace")


if __name__ == "__main__":
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print("入口页 http://%s:%s/" % (HOST, PORT))
    httpd.serve_forever()
