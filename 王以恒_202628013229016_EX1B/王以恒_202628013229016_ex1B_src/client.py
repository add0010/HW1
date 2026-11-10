"""Interactive TLS file-transfer client."""

from __future__ import annotations

import argparse
import getpass
import hashlib
import os
import shlex
import socket
import ssl
import tempfile
import time
from pathlib import Path

from protocol import CHUNK_SIZE, ProtocolError, recv_json, recv_stream, send_json, send_stream, valid_size

MAX_FILE_SIZE = 512 * 1024 * 1024
SOCKET_TIMEOUT = 90


def parse_command(line: str) -> list[str]:
    # posix=False preserves backslashes in common Windows paths; remove grouping quotes.
    parts = shlex.split(line, posix=False)
    return [part[1:-1] if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'" else part
            for part in parts]


def require_ok(response: dict, action: str) -> dict:
    if not response.get("ok"):
        raise ProtocolError(response.get("error", f"{action} failed"))
    return response


def upload(sock: ssl.SSLSocket, local_path: Path, remote_name: str | None) -> None:
    if not local_path.is_file():
        print(f"Local file not found: {local_path}")
        return
    size = local_path.stat().st_size
    if not valid_size(size, MAX_FILE_SIZE):
        print(f"File must be between 0 and {MAX_FILE_SIZE} bytes.")
        return
    digest = hashlib.sha256()
    with local_path.open("rb") as stream:
        while block := stream.read(CHUNK_SIZE):
            digest.update(block)
    name = remote_name or local_path.name
    send_json(sock, {"op": "upload", "name": name, "size": size, "sha256": digest.hexdigest()})
    require_ok(recv_json(sock), "upload preparation")
    deadline = time.monotonic() + 120 + size / (128 * 1024)
    with local_path.open("rb") as stream:
        send_stream(sock, stream, size, deadline=deadline)
    result = require_ok(recv_json(sock), "upload")
    print(f"Uploaded {result['name']} ({result['size']} bytes).")


def download(sock: ssl.SSLSocket, remote_name: str, local_path: Path | None) -> None:
    send_json(sock, {"op": "download", "name": remote_name})
    response = require_ok(recv_json(sock), "download")
    size = response.get("size")
    expected = response.get("sha256")
    if not valid_size(size, MAX_FILE_SIZE) or not isinstance(expected, str) or len(expected) != 64 or any(c not in "0123456789abcdef" for c in expected):
        raise ProtocolError("server returned invalid download metadata")
    destination = local_path or Path(response.get("name", remote_name)).name
    destination = Path(destination).expanduser().resolve()
    if destination.exists():
        answer = input(f"{destination} exists. Replace it after transfer? [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Download cancelled.")
            # Consume the payload before continuing on the persistent connection.
            with tempfile.TemporaryFile() as sink:
                recv_stream(sock, sink, size, deadline=time.monotonic() + 120 + size / (128 * 1024))
            return
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".part", dir=destination.parent)
    try:
        deadline = time.monotonic() + 120 + size / (128 * 1024)
        with os.fdopen(fd, "wb") as stream:
            actual = recv_stream(sock, stream, size, deadline=deadline)
            stream.flush()
            os.fsync(stream.fileno())
        if actual != expected:
            raise ProtocolError("downloaded file failed SHA-256 integrity check")
        os.replace(temporary, destination)
        print(f"Downloaded {destination} ({size} bytes; SHA-256 verified).")
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def run(args: argparse.Namespace) -> None:
    context = ssl.create_default_context(cafile=args.ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=args.client_cert, keyfile=args.client_key)
    with socket.create_connection((args.host, args.port), timeout=SOCKET_TIMEOUT) as raw:
        with context.wrap_socket(raw, server_hostname=args.server_name or args.host) as sock:
            sock.settimeout(SOCKET_TIMEOUT)
            password = getpass.getpass("Password: ")
            send_json(sock, {"op": "auth", "username": args.username, "password": password})
            welcome = require_ok(recv_json(sock), "authentication")
            print(f"Connected as {welcome['username']} using verified TLS.")
            print("Commands: list | upload <local-path> [remote-name] | download <remote-name> [local-path] | ping | quit")
            while True:
                try:
                    parts = parse_command(input("sft> ").strip())
                    if not parts:
                        continue
                    command = parts[0].lower()
                    if command == "list" and len(parts) == 1:
                        cursor = None
                        total = 0
                        while True:
                            request = {"op": "list"}
                            if cursor is not None:
                                request["cursor"] = cursor
                            send_json(sock, request)
                            result = require_ok(recv_json(sock), "list")
                            total += len(result["files"])
                            for item in result["files"]:
                                print(f"{item['name']}\t{item['size']} bytes")
                            cursor = result.get("next_cursor")
                            if not cursor:
                                break
                        if total == 0:
                            print("No files.")
                    elif command == "ping" and len(parts) == 1:
                        send_json(sock, {"op": "ping"})
                        require_ok(recv_json(sock), "ping")
                        print("Connection is alive.")
                    elif command == "upload" and len(parts) in {2, 3}:
                        upload(sock, Path(parts[1]).expanduser(), parts[2] if len(parts) == 3 else None)
                    elif command == "download" and len(parts) in {2, 3}:
                        download(sock, parts[1], Path(parts[2]).expanduser() if len(parts) == 3 else None)
                    elif command in {"quit", "exit"} and len(parts) == 1:
                        send_json(sock, {"op": "quit"})
                        recv_json(sock)
                        return
                    elif command == "help" and len(parts) == 1:
                        print("list | upload <local-path> [remote-name] | download <remote-name> [local-path] | ping | quit")
                    else:
                        print("Invalid command. Type help for the command list.")
                except (EOFError, KeyboardInterrupt):
                    print()
                    try:
                        send_json(sock, {"op": "quit"})
                        recv_json(sock)
                    except (OSError, ProtocolError):
                        pass
                    return
                except (ssl.SSLError, OSError) as exc:
                    print(f"Connection closed: {exc}")
                    return
                except (ProtocolError, KeyError, ValueError) as exc:
                    print(f"Request failed: {exc}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Secure file transfer client")
    parser.add_argument("host", help="server address")
    parser.add_argument("--port", type=int, default=9443)
    parser.add_argument("--username", required=True)
    parser.add_argument("--ca-cert", default="certs/mtls/ca-cert.pem",
                        help="trusted CA certificate used to verify the server")
    parser.add_argument("--client-cert", default="certs/mtls/client-cert.pem",
                        help="client certificate presented to the server")
    parser.add_argument("--client-key", default="certs/mtls/client-key.pem",
                        help="private key for the client certificate")
    parser.add_argument("--server-name", help="DNS name/IP in the server certificate SAN")
    args = parser.parse_args()
    try:
        run(args)
    except (OSError, ssl.SSLError, ProtocolError) as exc:
        raise SystemExit(f"Connection failed: {exc}") from exc


if __name__ == "__main__":
    main()
