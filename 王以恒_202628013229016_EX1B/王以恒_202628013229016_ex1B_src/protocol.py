"""Length-prefixed JSON framing shared by the client and server."""

from __future__ import annotations

import hashlib
import json
import socket
import struct
import time
from typing import Any, BinaryIO, Callable

HEADER = struct.Struct("!I")
MAX_HEADER_SIZE = 64 * 1024
CHUNK_SIZE = 1024 * 1024


class ProtocolError(Exception):
    """Raised when a peer sends a malformed or incomplete protocol frame."""


def recv_exact(sock: socket.socket, size: int, *, deadline: float | None = None) -> bytes:
    if size < 0:
        raise ProtocolError("negative byte count")
    original_timeout = sock.gettimeout()
    if deadline is None and original_timeout is not None:
        deadline = time.monotonic() + original_timeout
    chunks = bytearray()
    try:
        while len(chunks) < size:
            if deadline is not None:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise socket.timeout("frame or transfer deadline exceeded")
                sock.settimeout(remaining_time if original_timeout is None else min(original_timeout, remaining_time))
            part = sock.recv(min(CHUNK_SIZE, size - len(chunks)))
            if not part:
                raise ConnectionError("peer closed the connection")
            chunks.extend(part)
    finally:
        if sock.gettimeout() != original_timeout:
            sock.settimeout(original_timeout)
    return bytes(chunks)


def send_json(sock: socket.socket, message: dict[str, Any]) -> None:
    raw = json.dumps(message, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not raw or len(raw) > MAX_HEADER_SIZE:
        raise ProtocolError("JSON header is too large")
    sock.sendall(HEADER.pack(len(raw)))
    sock.sendall(raw)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    (size,) = HEADER.unpack(recv_exact(sock, HEADER.size))
    if size == 0 or size > MAX_HEADER_SIZE:
        raise ProtocolError("invalid JSON header length")
    try:
        value = json.loads(recv_exact(sock, size).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProtocolError("invalid UTF-8 JSON header") from exc
    if not isinstance(value, dict):
        raise ProtocolError("JSON header must be an object")
    return value


def send_stream(
    sock: socket.socket,
    stream: BinaryIO,
    size: int,
    *,
    deadline: float | None = None,
    progress: Callable[[int], None] | None = None,
) -> str:
    """Send exactly size bytes and return their SHA-256 digest."""
    remaining = size
    digest = hashlib.sha256()
    original_timeout = sock.gettimeout()
    try:
        while remaining:
            if deadline is not None:
                remaining_time = deadline - time.monotonic()
                if remaining_time <= 0:
                    raise socket.timeout("transfer deadline exceeded")
                sock.settimeout(remaining_time if original_timeout is None else min(original_timeout, remaining_time))
            block = stream.read(min(CHUNK_SIZE, remaining))
            if not block:
                raise OSError("file ended before its declared size")
            sock.sendall(block)
            digest.update(block)
            remaining -= len(block)
            if progress is not None:
                progress(size - remaining)
    finally:
        if sock.gettimeout() != original_timeout:
            sock.settimeout(original_timeout)
    return digest.hexdigest()


def recv_stream(
    sock: socket.socket,
    stream: BinaryIO,
    size: int,
    *,
    deadline: float | None = None,
    progress: Callable[[int], None] | None = None,
) -> str:
    """Receive exactly size bytes, writing them incrementally to stream."""
    remaining = size
    digest = hashlib.sha256()
    while remaining:
        block = recv_exact(sock, min(CHUNK_SIZE, remaining), deadline=deadline)
        stream.write(block)
        digest.update(block)
        remaining -= len(block)
        if progress is not None:
            progress(size - remaining)
    return digest.hexdigest()


def valid_size(value: Any, maximum: int) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= maximum
