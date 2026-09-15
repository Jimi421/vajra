#!/usr/bin/env python3
"""Tiny stdlib-only HTTP file server with GET/POST/PUT upload + download.

No third-party deps, no `cgi` (removed in Python 3.13). Recursively browse
folders, click files to download, upload with the browser, or PUT with curl.

    python3 fileserver.py                  # serve cwd on :8000
    python3 fileserver.py -p 9001          # custom port
    python3 fileserver.py -d /tmp/loot     # custom directory
    python3 fileserver.py -p 9001 -d /tmp/loot
"""
from __future__ import annotations

import argparse
import errno
import glob
import html
import os
import re
import signal
import socket
import sys
import time
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import quote, unquote, urlsplit

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>fileserver — {cwd}</title>
<style>
  :root {{ color-scheme: light dark; }}
  * {{ box-sizing: border-box; }}
  body {{
    font: 15px/1.5 ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    max-width: 640px; margin: 2.5rem auto; padding: 0 1.25rem;
    background: #0d1117; color: #e6edf3;
  }}
  h1 {{ font-size: 1.05rem; font-weight: 600; margin: 0 0 .25rem; }}
  .path {{ color: #7d8590; font-size: .85rem; margin-bottom: 1.75rem; word-break: break-all; }}
  .drop {{
    border: 1px dashed #30363d; border-radius: 10px; padding: 1.25rem;
    display: flex; gap: .75rem; align-items: center; flex-wrap: wrap;
    transition: border-color .15s, background .15s;
  }}
  .drop.hover {{ border-color: #58a6ff; background: #131c2b; }}
  input[type=file] {{ flex: 1 1 12rem; min-width: 0; color: #e6edf3; }}
  button {{
    font: inherit; font-weight: 600; cursor: pointer;
    background: #238636; color: #fff; border: 0; border-radius: 7px;
    padding: .5rem 1.1rem;
  }}
  button:hover {{ background: #2ea043; }}
  button:disabled {{ opacity: .55; cursor: default; }}
  ul {{ list-style: none; padding: 0; margin: 1.75rem 0 0; }}
  li {{ padding: .4rem 0; border-bottom: 1px solid #21262d; display: flex; justify-content: space-between; gap: 1rem; }}
  a {{ color: #58a6ff; text-decoration: none; word-break: break-all; }}
  a:hover {{ text-decoration: underline; }}
  .size {{ color: #7d8590; font-size: .8rem; white-space: nowrap; }}
  .empty {{ color: #7d8590; font-style: italic; }}
</style>
</head>
<body>
  <h1>fileserver</h1>
  <div class="path">{cwd}</div>

  <form class="drop" id="f" method="POST" enctype="multipart/form-data">
    <input type="file" name="file" id="file" multiple required>
    <button type="submit">Upload</button>
  </form>

  <ul>{listing}</ul>

  <script>
    const form = document.getElementById('f');
    const drop = form;
    ['dragenter','dragover'].forEach(e => drop.addEventListener(e, ev => {{
      ev.preventDefault(); drop.classList.add('hover');
    }}));
    ['dragleave','drop'].forEach(e => drop.addEventListener(e, ev => {{
      ev.preventDefault(); drop.classList.remove('hover');
    }}));
    drop.addEventListener('drop', ev => {{
      document.getElementById('file').files = ev.dataTransfer.files;
    }});
  </script>
</body>
</html>"""


def human(n: int) -> str:
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024:
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}P"


def parse_multipart(body: bytes, boundary: bytes):
    """Yield (filename, data) for each file part. Pure stdlib, no cgi."""
    delim = b"--" + boundary
    for part in body.split(delim):
        if not part or part == b"--\r\n" or part == b"\r\n":
            continue
        part = part[2:] if part.startswith(b"\r\n") else part
        part = part[:-2] if part.endswith(b"\r\n") else part
        head, sep, data = part.partition(b"\r\n\r\n")
        if not sep:
            continue
        m = re.search(rb'filename="([^"]*)"', head)
        if not m or not m.group(1):
            continue
        yield m.group(1).decode("utf-8", "replace"), data


class Handler(SimpleHTTPRequestHandler):
    quiet = False

    def _root(self) -> Path:
        return Path(self.directory).resolve()

    def _url_path(self) -> str:
        return unquote(urlsplit(self.path).path)

    def _safe_target(self, url_path: str | None = None) -> Path:
        """Map a URL path into the served tree, rejecting traversal/symlink escapes."""
        raw = self._url_path() if url_path is None else url_path
        if "\x00" in raw or "\\" in raw:
            raise ValueError("invalid path")

        parts = []
        for part in raw.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                raise ValueError("path traversal")
            parts.append(part)

        root = self._root()
        target = root.joinpath(*parts).resolve(strict=False)
        try:
            target.relative_to(root)
        except ValueError as exc:
            raise ValueError("outside served directory") from exc
        return target

    def _virtual_path(self, target: Path) -> str:
        rel = target.relative_to(self._root())
        if not rel.parts:
            return "/"
        return "/" + "/".join(rel.parts) + "/"

    def _send_directory(self, directory: Path) -> None:
        rows = []

        if directory != self._root():
            rows.append(
                '<li><a href="../">📁 ../</a>'
                '<span class="size">parent</span></li>'
            )

        try:
            entries = sorted(
                directory.iterdir(),
                key=lambda x: (not x.is_dir(), x.name.lower()),
            )
        except OSError as e:
            self.send_error(403, f"Cannot list directory: {e}")
            return

        root = self._root()
        for p in entries:
            # Do not advertise symlinks that resolve outside the served tree.
            try:
                resolved = p.resolve()
                resolved.relative_to(root)
            except (OSError, ValueError):
                continue

            label = html.escape(p.name)
            href = quote(p.name, safe="")
            try:
                if p.is_dir():
                    rows.append(
                        f'<li><a href="{href}/">📁 {label}/</a>'
                        '<span class="size">dir</span></li>'
                    )
                elif p.is_file():
                    rows.append(
                        f'<li><a href="{href}" download>📄 {label}</a>'
                        f'<span class="size">{human(p.stat().st_size)}</span></li>'
                    )
            except OSError:
                continue

        listing = "".join(rows) or '<li class="empty">no files yet</li>'
        shown = html.escape(str(directory))
        page = PAGE.format(cwd=shown, listing=listing)
        body = page.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        try:
            target = self._safe_target()
        except ValueError:
            self.send_error(403, "Path outside served directory")
            return

        if target.is_dir():
            # Keep relative links/forms sane by canonicalizing directory URLs.
            if not urlsplit(self.path).path.endswith("/"):
                location = urlsplit(self.path).path + "/"
                self.send_response(301)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()
                return
            self._send_directory(target)
            return

        if not target.exists():
            self.send_error(404, "File not found")
            return

        # SimpleHTTPRequestHandler handles MIME types, Range requests, etc.
        super().do_GET()

    def do_PUT(self):
        """Create or replace a file anywhere inside an existing served folder.

        Examples:
            curl -T linpeas.sh http://HOST:8000/tools/linux/linpeas.sh
            curl -T winPEAS.exe http://HOST:8000/tools/windows/winPEAS.exe
        """
        raw_path = self._url_path()
        if not raw_path or raw_path.endswith("/"):
            self.send_error(400, "PUT requires a destination filename")
            return

        try:
            target = self._safe_target(raw_path)
        except ValueError:
            self.send_error(403, "Path outside served directory")
            return

        if target.exists() and target.is_dir():
            self.send_error(409, "Destination is a directory")
            return
        if not target.parent.is_dir():
            self.send_error(409, "Parent directory does not exist")
            return

        length_header = self.headers.get("Content-Length")
        if length_header is None:
            self.send_error(411, "Content-Length required")
            return
        try:
            length = int(length_header)
        except ValueError:
            self.send_error(400, "Invalid Content-Length")
            return
        if length < 0:
            self.send_error(400, "Invalid Content-Length")
            return

        existed = target.exists()
        data = self.rfile.read(length)
        try:
            target.write_bytes(data)
        except OSError as e:
            self.send_error(500, f"Could not write file: {e}")
            return

        rel = target.relative_to(self._root()).as_posix()
        print(f"  + PUT {rel} ({human(len(data))})")

        if existed:
            self.send_response(204)
            self.end_headers()
        else:
            self.send_response(201)
            self.send_header("Location", "/" + quote(rel, safe="/"))
            self.send_header("Content-Length", "0")
            self.end_headers()

    def do_POST(self):
        """Multipart upload into the directory represented by the request URL."""
        try:
            directory = self._safe_target()
        except ValueError:
            self.send_error(403, "Path outside served directory")
            return
        if not directory.is_dir():
            self.send_error(404, "Upload destination is not a directory")
            return

        ctype = self.headers.get("Content-Type", "")
        m = re.search(r"boundary=([^;]+)", ctype)
        try:
            length = int(self.headers.get("Content-Length", 0))
        except ValueError:
            length = 0
        if "multipart/form-data" not in ctype or not m or length <= 0:
            self.send_error(400, "Expected a multipart file upload")
            return

        boundary = m.group(1).strip().strip('"').encode()
        body = self.rfile.read(length)
        saved = 0
        for filename, data in parse_multipart(body, boundary):
            safe = Path(filename).name  # strip client-provided path components
            if not safe or safe in (".", ".."):
                continue
            target = directory / safe
            try:
                target.write_bytes(data)
            except OSError as e:
                self.send_error(500, f"Could not write {safe}: {e}")
                return
            rel = target.relative_to(self._root()).as_posix()
            print(f"  + POST {rel} ({human(len(data))})")
            saved += 1

        if saved:
            # Return to the directory the user uploaded into.
            loc = urlsplit(self.path).path
            if not loc.endswith("/"):
                loc += "/"
            self.send_response(303)
            self.send_header("Location", loc)
            self.end_headers()
        else:
            self.send_error(400, "No file in upload")

    def log_message(self, fmt, *args):
        if not self.quiet:
            print(f"  {self.address_string()} {fmt % args}")


def interface_ips():
    """List (ifname, ipv4) for every up interface. Linux via ioctl; stdlib only.

    Returns [] if the ioctl path isn't available (non-Linux), letting callers
    fall back to the default-route guess.
    """
    try:
        import fcntl
        import struct
    except ImportError:
        return []

    out = []
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        for _, name in socket.if_nameindex():
            try:
                packed = struct.pack("256s", name.encode()[:15])
                res = fcntl.ioctl(s.fileno(), 0x8915, packed)  # SIOCGIFADDR
                out.append((name, socket.inet_ntoa(res[20:24])))
            except OSError:
                continue  # interface is down or has no IPv4
    finally:
        s.close()
    return out


def default_route_ip() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


# Interface-name prefixes that mean "this is your VPN / lab tunnel".
_VPN_PREFIXES = ("tun", "tap", "wg", "ppp")


def print_addresses(port: int, host: str) -> None:
    """Print reachable URLs, flagging the VPN/tunnel address for lab targets."""
    ips = [(n, ip) for n, ip in interface_ips() if not ip.startswith("127.")]
    vpn = [(n, ip) for n, ip in ips if n.startswith(_VPN_PREFIXES)]
    lan = [(n, ip) for n, ip in ips if not n.startswith(_VPN_PREFIXES)]

    bound = "all interfaces" if host in ("0.0.0.0", "") else host
    print(f"Serving on port {port}  ({bound})")

    if vpn:
        for n, ip in vpn:
            print(f"  → {n:<6} http://{ip}:{port}/    ← use this for the lab target")
    for n, ip in lan:
        print(f"    {n:<6} http://{ip}:{port}/")
    if not ips:  # ioctl unavailable — fall back to the old guess
        print(f"    http://{default_route_ip()}:{port}/")
    print(f"    lo     http://127.0.0.1:{port}/    (local)")

    if not vpn:
        print("  (no tun/tap/wg interface detected — is your VPN up? check `ip a`)")

    # Ready-to-copy curl commands. Prefer the VPN/lab IP when available.
    curl_ip = vpn[0][1] if vpn else (lan[0][1] if lan else default_route_ip())
    print("\nCurl examples:")
    print(f'  DOWNLOAD: curl -O http://{curl_ip}:{port}/FILE')
    print(f'  POST:     curl -F "file=@C:/temp/file.exe" http://{curl_ip}:{port}/')
    print(f'  PUT:      curl -T ./file.exe http://{curl_ip}:{port}/file.exe')


def port_free(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
            return True
        except OSError:
            return False


def next_free_port(host: str, start: int, span: int = 64):
    for p in range(start, min(start + span, 65536)):
        if port_free(host, p):
            return p
    return None


def _read(path: str) -> str:
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def procs_on_port(port: int):
    """Best-effort list of (pid, comm, cmdline) LISTENing on `port`.

    Pure stdlib via /proc — no ss/lsof/fuser needed. Linux only; returns []
    on other platforms or if the holder can't be identified (e.g. owned by
    another user and we're not root).
    """
    inodes = set()
    for tbl in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(tbl) as f:
                next(f, None)  # header
                for line in f:
                    parts = line.split()
                    if len(parts) < 10 or parts[3] != "0A":  # 0A = LISTEN
                        continue
                    if int(parts[1].rsplit(":", 1)[1], 16) == port:
                        inodes.add(parts[9])
        except OSError:
            pass
    if not inodes:
        return []

    pids = set()
    for fd in glob.glob("/proc/[0-9]*/fd/*"):
        try:
            link = os.readlink(fd)
        except OSError:
            continue
        if link.startswith("socket:[") and link[8:-1] in inodes:
            pids.add(int(fd.split("/")[2]))

    out = []
    for pid in sorted(pids):
        comm = _read(f"/proc/{pid}/comm").strip() or "?"
        cmd = _read(f"/proc/{pid}/cmdline").replace("\x00", " ").strip() or comm
        out.append((pid, comm, cmd))
    return out


def kill_pid(pid: int):
    """SIGTERM, then SIGKILL if it won't go. Returns (ok, message)."""
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        return True, "already gone"
    except PermissionError:
        return False, "permission denied (try sudo)"
    for _ in range(15):
        time.sleep(0.1)
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True, f"PID {pid} terminated"
    try:
        os.kill(pid, signal.SIGKILL)
        return True, f"PID {pid} killed (SIGKILL)"
    except OSError as e:
        return False, str(e)


def resolve_port(host: str, port: int, auto: bool) -> int:
    """Return an available port, prompting on conflict unless auto/non-tty."""
    while not port_free(host, port):
        holders = procs_on_port(port)
        alt = next_free_port(host, port + 1)

        if holders:
            pid, comm, cmd = holders[0]
            short = cmd if len(cmd) <= 64 else cmd[:61] + "..."
            extra = f"  (+{len(holders) - 1} more)" if len(holders) > 1 else ""
            print(f"Port {port} is in use by PID {pid} ({comm}){extra}")
            print(f"  {short}")
        else:
            print(f"Port {port} is already in use "
                  f"(couldn't identify the process — try running with sudo).")

        # Non-interactive (script/pipe) or -a: fall back silently, never kill.
        if auto or not sys.stdin.isatty():
            if alt is None:
                sys.exit("No free port found nearby. Exiting.")
            print(f"→ falling back to port {alt}\n")
            return alt

        opts = []
        if alt:
            opts.append(f"[Enter] use {alt}")
        opts.append("type a port")
        if holders:
            opts.append(f"k = kill PID {holders[0][0]} & reuse {port}")
        opts.append("n = quit")
        choice = input("  " + "   ·   ".join(opts) + "\n> ").strip().lower()

        if choice in ("", "y", "yes") and alt:
            return alt
        if choice.isdigit():
            port = int(choice)
            continue
        if choice == "k" and holders:
            ok, msg = kill_pid(holders[0][0])
            print(f"  {msg}")
            if ok:
                time.sleep(0.2)  # let the socket release
                continue          # loop re-checks port_free(port)
            print("  pick another port instead.")
            continue
        sys.exit("Aborted.")
    return port


def main():
    ap = argparse.ArgumentParser(description="Tiny upload/download file server.")
    ap.add_argument("-p", "--port", type=int, default=8000)
    ap.add_argument("-d", "--dir", default=".", help="directory to serve (default: cwd)")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("-a", "--auto-port", action="store_true",
                    help="on conflict, auto-pick the next free port (no prompt)")
    ap.add_argument("-q", "--quiet", action="store_true",
                    help="suppress per-request access logs")
    args = ap.parse_args()

    directory = str(Path(args.dir).resolve())
    port = resolve_port(args.host, args.port, args.auto_port)
    Handler.quiet = args.quiet

    def handler(*a, **kw):
        return Handler(*a, directory=directory, **kw)

    try:
        srv = ThreadingHTTPServer((args.host, port), handler)
    except OSError as e:
        # Rare TOCTOU race: something grabbed the port between probe and bind.
        if e.errno == errno.EADDRINUSE:
            sys.exit(f"Port {port} was taken just now — rerun or pass -a.")
        raise
    print(f"Serving {directory}")
    print_addresses(port, args.host)
    print("Browse folders recursively; browser uploads land in the current folder. Ctrl-C to stop.\n")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
