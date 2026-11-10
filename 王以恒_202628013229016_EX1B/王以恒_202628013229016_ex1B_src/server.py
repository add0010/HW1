"""TLS-protected, multi-user file-transfer server using only the Python stdlib."""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import socket
import socketserver
import ssl
import tempfile
import threading
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from protocol import CHUNK_SIZE, ProtocolError, recv_json, recv_exact, send_json, send_stream, valid_size

LOG = logging.getLogger("sft.server")
PBKDF2_ROUNDS = 310_000
MAX_FILE_SIZE = 512 * 1024 * 1024
MAX_USER_STORAGE = 2 * 1024 * 1024 * 1024
MAX_CONNECTIONS = 64
MAX_LIST_ITEMS = 50
SOCKET_TIMEOUT = 90
AUTH_WINDOW_SECONDS = 60
AUTH_FAILURES_PER_IP = 5
USERNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
NAME_RE = re.compile(r'^[^/\\:"|?*<>\x00-\x1f\x7f]{1,255}$')
WINDOWS_RESERVED_NAMES = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10))}


def derive_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)


def load_users(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read user database {path}: {exc}") from exc
    if not isinstance(value, dict) or not isinstance(value.get("users"), dict):
        raise ValueError("user database has an invalid format")
    return value["users"]


def save_users(path: Path, users: dict[str, dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            json.dump({"version": 1, "users": users}, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.chmod(temporary, 0o600)
        except OSError:
            pass
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def add_user(path: Path, username: str) -> None:
    if not USERNAME_RE.fullmatch(username):
        raise ValueError("username must be 1-32 ASCII letters, digits, dots, underscores or hyphens")
    users = load_users(path)
    if username in users:
        raise ValueError(f"user {username!r} already exists")
    password = getpass.getpass("New password (at least 12 characters): ")
    confirmation = getpass.getpass("Repeat password: ")
    if len(password) < 12:
        raise ValueError("password must contain at least 12 characters")
    if not hmac.compare_digest(password, confirmation):
        raise ValueError("passwords do not match")
    salt = secrets.token_bytes(16)
    users[username] = {
        "salt": base64.b64encode(salt).decode("ascii"),
        "hash": base64.b64encode(derive_password(password, salt)).decode("ascii"),
        "rounds": PBKDF2_ROUNDS,
    }
    save_users(path, users)
    print(f"Added user {username!r} to {path}.")


class AuthLimiter:
    """Small bounded per-IP failure window for authentication requests."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: dict[str, deque[float]] = defaultdict(deque)

    def allowed(self, address: str) -> bool:
        now = time.monotonic()
        with self._lock:
            attempts = self._failures.get(address)
            if attempts is None:
                if len(self._failures) >= 4096:
                    expired = [key for key, history in self._failures.items()
                               if not history or now - history[-1] > AUTH_WINDOW_SECONDS]
                    for key in expired:
                        self._failures.pop(key, None)
                    if len(self._failures) >= 4096:
                        return False
                attempts = self._failures[address]
            while attempts and now - attempts[0] > AUTH_WINDOW_SECONDS:
                attempts.popleft()
            return len(attempts) < AUTH_FAILURES_PER_IP

    def failed(self, address: str) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._failures.get(address)
            if attempts is None:
                if len(self._failures) >= 4096:
                    return
                attempts = self._failures[address]
            while attempts and now - attempts[0] > AUTH_WINDOW_SECONDS:
                attempts.popleft()
            attempts.append(now)


def safe_filename(value: Any) -> str:
    if not isinstance(value, str) or not NAME_RE.fullmatch(value):
        raise ValueError("filename must be a single path component")
    if value in {".", ".."} or value.endswith((".", " ")):
        raise ValueError("filename is not allowed")
    stem = value.split(".", 1)[0].upper()
    if stem in WINDOWS_RESERVED_NAMES:
        raise ValueError("filename is reserved on Windows")
    return value


def session_home(root: Path, username: str) -> Path:
    home = root / username
    if home.is_symlink():
        raise OSError("user storage directory cannot be a symbolic link")
    home.mkdir(mode=0o700, parents=True, exist_ok=True)
    if home.resolve().name != username or home.resolve().parent != root.resolve():
        raise OSError("user storage directory escapes the storage root")
    try:
        os.chmod(home, 0o700)
    except OSError:
        pass
    return home


class TransferHandler(socketserver.BaseRequestHandler):
    def setup(self) -> None:
        self.request.settimeout(SOCKET_TIMEOUT)
        self.request.do_handshake()

    def handle(self) -> None:
        peer_ip = str(self.client_address[0])
        try:
            hello = recv_json(self.request)
            if hello.get("op") != "auth":
                send_json(self.request, {"ok": False, "error": "authentication required"})
                return
            if not self.server.auth_limiter.allowed(peer_ip):  # type: ignore[attr-defined]
                send_json(self.request, {"ok": False, "error": "authentication temporarily unavailable"})
                return
            username = hello.get("username")
            password = hello.get("password")
            if (not isinstance(username, str) or len(username) > 32 or
                    not isinstance(password, str) or len(password) > 1024):
                self._auth_failure(peer_ip)
                return
            users = self.server.users  # type: ignore[attr-defined]
            record = users.get(username)
            valid = False
            if record is not None:
                try:
                    salt = base64.b64decode(record["salt"], validate=True)
                    expected = base64.b64decode(record["hash"], validate=True)
                    rounds = int(record["rounds"])
                    if not 100_000 <= rounds <= 2_000_000:
                        raise ValueError("invalid password hash rounds")
                    valid = hmac.compare_digest(derive_password(password, salt) if rounds == PBKDF2_ROUNDS else hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds), expected)
                except (KeyError, TypeError, ValueError):
                    valid = False
            else:
                # Spend comparable work for unknown usernames to reduce enumeration by timing.
                derive_password(password, b"\0" * 16)
            if not valid:
                self._auth_failure(peer_ip)
                return

            self.username = username
            self.home = session_home(self.server.storage_root, username)  # type: ignore[attr-defined]
            send_json(self.request, {"ok": True, "event": "authenticated", "username": username})
            LOG.info("authenticated user=%s peer=%s", username, peer_ip)
            while True:
                request = recv_json(self.request)
                op = request.get("op")
                try:
                    if op == "list":
                        self._list_files(request)
                    elif op == "upload":
                        self._upload(request)
                    elif op == "download":
                        self._download(request)
                    elif op == "delete":
                        self._delete(request)
                    elif op == "ping":
                        send_json(self.request, {"ok": True, "event": "pong"})
                    elif op == "quit":
                        send_json(self.request, {"ok": True, "event": "bye"})
                        return
                    else:
                        send_json(self.request, {"ok": False, "error": "unsupported operation"})
                except ValueError as exc:
                    LOG.warning("request rejected user=%s op=%s reason=%s", self.username, op, exc)
                    send_json(self.request, {"ok": False, "error": str(exc)[:200]})
        except (ConnectionError, OSError, ProtocolError, ssl.SSLError) as exc:
            LOG.info("connection closed peer=%s reason=%s", peer_ip, exc)

    def _auth_failure(self, peer_ip: str) -> None:
        self.server.auth_limiter.failed(peer_ip)  # type: ignore[attr-defined]
        send_json(self.request, {"ok": False, "error": "invalid credentials"})

    def _list_files(self, request: dict[str, Any]) -> None:
        cursor = request.get("cursor")
        if cursor is not None and (not isinstance(cursor, str) or len(cursor) > 255):
            raise ValueError("invalid list cursor")
        cursor_key = (cursor.casefold(), cursor) if cursor is not None else None
        entries = []
        paths = sorted(self.home.iterdir(), key=lambda item: (item.name.casefold(), item.name))
        for path in paths:
            if cursor_key is not None and (path.name.casefold(), path.name) <= cursor_key:
                continue
            try:
                if not path.is_symlink() and path.is_file() and not path.name.startswith(".upload-"):
                    entries.append({"name": path.name, "size": path.stat().st_size})
                    if len(entries) >= MAX_LIST_ITEMS:
                        break
            except OSError:
                continue
        next_cursor = entries[-1]["name"] if len(entries) == MAX_LIST_ITEMS else None
        send_json(self.request, {"ok": True, "files": entries, "next_cursor": next_cursor})

    def _upload(self, request: dict[str, Any]) -> None:
        name = safe_filename(request.get("name"))
        size = request.get("size")
        digest_expected = request.get("sha256")
        if not valid_size(size, self.server.max_file_size):  # type: ignore[attr-defined]
            raise ValueError("file size is outside the configured limit")
        if not isinstance(digest_expected, str) or not re.fullmatch(r"[0-9a-f]{64}", digest_expected):
            raise ValueError("invalid SHA-256 digest")
        target = self.home / name
        if target.is_symlink():
            raise ValueError("symbolic-link targets are not allowed")
        with self.server.user_locks[self.username]:  # type: ignore[attr-defined]
            used = 0
            for entry in self.home.iterdir():
                if not entry.is_symlink() and entry.is_file():
                    try:
                        used += entry.stat().st_size
                    except OSError:
                        continue
            replaced_size = target.stat().st_size if target.is_file() and not target.is_symlink() else 0
            if used - replaced_size + size > self.server.max_user_storage:  # type: ignore[attr-defined]
                raise ValueError("user storage quota would be exceeded")
            self._receive_upload(name, size, digest_expected, target)

    def _receive_upload(self, name: str, size: int, digest_expected: str, target: Path) -> None:
        try:
            fd, temporary = tempfile.mkstemp(prefix=".upload-", suffix=".part", dir=self.home)
        except OSError as exc:
            raise ValueError("server storage is unavailable") from exc
        try:
            send_json(self.request, {"ok": True, "event": "ready"})
            digest = hashlib.sha256()
            remaining = size
            deadline = time.monotonic() + 120 + size / (128 * 1024)
            with os.fdopen(fd, "wb") as stream:
                fd = -1
                while remaining:
                    block = recv_exact(self.request, min(CHUNK_SIZE, remaining), deadline=deadline)
                    stream.write(block)
                    digest.update(block)
                    remaining -= len(block)
                stream.flush()
                os.fsync(stream.fileno())
            if not hmac.compare_digest(digest.hexdigest(), digest_expected):
                raise ValueError("uploaded file failed SHA-256 integrity check")
            if target.is_symlink():
                raise ValueError("symbolic-link targets are not allowed")
            os.replace(temporary, target)
            send_json(self.request, {"ok": True, "event": "uploaded", "name": name, "size": size})
            LOG.info("upload complete user=%s name=%s size=%s", self.username, name, size)
        finally:
            if fd >= 0:
                os.close(fd)
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _download(self, request: dict[str, Any]) -> None:
        name = safe_filename(request.get("name"))
        path = self.home / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("file not found")
        size = path.stat().st_size
        if not valid_size(size, self.server.max_file_size):  # type: ignore[attr-defined]
            raise ValueError("file size is outside the configured limit")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(CHUNK_SIZE):
                digest.update(block)
        expected = digest.hexdigest()
        send_json(self.request, {"ok": True, "event": "download", "name": name, "size": size, "sha256": expected})
        deadline = time.monotonic() + 120 + size / (128 * 1024)
        with path.open("rb") as stream:
            sent_digest = send_stream(self.request, stream, size, deadline=deadline)
        if not hmac.compare_digest(sent_digest, expected):
            LOG.warning("file changed during download user=%s name=%s", self.username, name)
        LOG.info("download complete user=%s name=%s size=%s", self.username, name, size)

    def _delete(self, request: dict[str, Any]) -> None:
        name = safe_filename(request.get("name"))
        target = self.home / name
        with self.server.user_locks[self.username]:  # type: ignore[attr-defined]
            if target.is_symlink() or not target.is_file():
                raise ValueError("file not found")
            size = target.stat().st_size
            try:
                target.unlink()
            except OSError as exc:
                raise ValueError("file could not be deleted") from exc
        send_json(self.request, {"ok": True, "event": "deleted", "name": name, "size": size})
        LOG.info("delete complete user=%s name=%s size=%s", self.username, name, size)


class BoundedTLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    block_on_close = True
    request_queue_size = 128

    def __init__(self, address: tuple[str, int], handler: type[TransferHandler], *, context: ssl.SSLContext,
                 storage_root: Path, users: dict[str, dict[str, Any]], max_file_size: int,
                 max_connections: int) -> None:
        self.ssl_context = context
        self.storage_root = storage_root
        self.users = users
        self.max_file_size = max_file_size
        self.max_user_storage = MAX_USER_STORAGE
        self.max_connections = max_connections
        self.user_locks = {username: threading.Lock() for username in users}
        self.auth_limiter = AuthLimiter()
        self._slots = threading.BoundedSemaphore(max_connections)
        super().__init__(address, handler)

    def get_request(self) -> tuple[socket.socket, Any]:
        connection, address = super().get_request()
        connection.settimeout(SOCKET_TIMEOUT)
        try:
            secured = self.ssl_context.wrap_socket(connection, server_side=True, do_handshake_on_connect=False)
            secured.settimeout(SOCKET_TIMEOUT)
            return secured, address
        except (OSError, ssl.SSLError):
            connection.close()
            raise

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, client_address)
        except BaseException:
            self._slots.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def serve(args: argparse.Namespace) -> None:
    cert = Path(args.cert).expanduser().resolve()
    key = Path(args.key).expanduser().resolve()
    client_ca = Path(args.client_ca).expanduser().resolve()
    storage = Path(args.storage).expanduser().resolve()
    users_path = Path(args.users).expanduser().resolve()
    users = load_users(users_path)
    if not users:
        raise SystemExit(f"No users configured. Add one with: python server.py add-user USER --users {users_path}")
    if not cert.is_file() or not key.is_file() or not client_ca.is_file():
        raise SystemExit(
            "TLS certificate, private key, or client CA is missing. "
            "Run scripts/generate_demo_cert.ps1 first."
        )
    storage.mkdir(parents=True, exist_ok=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    context.load_cert_chain(certfile=str(cert), keyfile=str(key))
    context.load_verify_locations(cafile=str(client_ca))
    context.verify_mode = ssl.CERT_REQUIRED
    server = BoundedTLSServer((args.host, args.port), TransferHandler, context=context,
                              storage_root=storage, users=users,
                              max_file_size=args.max_file_size, max_connections=args.max_connections)
    LOG.info("listening with mutual TLS on %s:%s; storage=%s; users=%s", args.host, args.port, storage, len(users))
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        LOG.info("shutdown requested")
    finally:
        server.shutdown()
        server.server_close()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Secure file transfer server")
    commands = parser.add_subparsers(dest="command", required=True)
    user_parser = commands.add_parser("add-user", help="add a user with a salted password hash")
    user_parser.add_argument("username")
    user_parser.add_argument("--users", default="users.json")
    serve_parser = commands.add_parser("serve", help="start the TLS file-transfer server")
    serve_parser.add_argument("--host", default="0.0.0.0")
    serve_parser.add_argument("--port", type=int, default=9443)
    serve_parser.add_argument("--storage", default="storage")
    serve_parser.add_argument("--users", default="users.json")
    serve_parser.add_argument("--cert", default="certs/mtls/server-cert.pem")
    serve_parser.add_argument("--key", default="certs/mtls/server-key.pem")
    serve_parser.add_argument("--client-ca", default="certs/mtls/ca-cert.pem",
                              help="CA certificate used to verify client certificates")
    serve_parser.add_argument("--max-file-size", type=int, default=MAX_FILE_SIZE)
    serve_parser.add_argument("--max-connections", type=int, default=MAX_CONNECTIONS)
    return parser


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    args = build_parser().parse_args()
    try:
        if args.command == "add-user":
            add_user(Path(args.users).expanduser().resolve(), args.username)
        else:
            if not 1 <= args.port <= 65535:
                raise ValueError("port must be between 1 and 65535")
            if not 1 <= args.max_connections <= 512:
                raise ValueError("max-connections must be between 1 and 512")
            if not 0 <= args.max_file_size <= 2**40:
                raise ValueError("max-file-size must be between 0 and 1 TiB")
            serve(args)
    except (OSError, ValueError) as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
