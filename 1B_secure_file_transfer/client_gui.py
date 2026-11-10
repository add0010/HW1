"""Desktop GUI client for the mutual-TLS secure file-transfer service."""

from __future__ import annotations

import hashlib
import os
import queue
import re
import socket
import ssl
import tempfile
import threading
import time
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from protocol import CHUNK_SIZE, ProtocolError, recv_json, recv_stream, send_json, send_stream, valid_size

PROJECT_DIR = Path(__file__).resolve().parent
CERT_DIR = PROJECT_DIR / "certs" / "mtls"
DEFAULT_CA_CERT = Path("certs") / "mtls" / "ca-cert.pem"
DEFAULT_CLIENT_CERT = Path("certs") / "mtls" / "client-cert.pem"
DEFAULT_CLIENT_KEY = Path("certs") / "mtls" / "client-key.pem"
MAX_FILE_SIZE = 512 * 1024 * 1024
SOCKET_TIMEOUT = 90


class RemoteError(Exception):
    """A well-formed error returned by the server; the session may continue."""


def require_ok(response: dict, action: str) -> dict:
    if not response.get("ok"):
        raise RemoteError(response.get("error", f"{action} failed"))
    return response


def format_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{int(value)} B" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def create_authenticated_connection(
    host: str,
    port: int,
    username: str,
    password: str,
    ca_cert: str,
    client_cert: str,
    client_key: str,
) -> ssl.SSLSocket:
    context = ssl.create_default_context(cafile=ca_cert)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_cert_chain(certfile=client_cert, keyfile=client_key)

    raw = socket.create_connection((host, port), timeout=SOCKET_TIMEOUT)
    secured: ssl.SSLSocket | None = None
    try:
        secured = context.wrap_socket(raw, server_hostname=host)
        secured.settimeout(SOCKET_TIMEOUT)
        send_json(secured, {"op": "auth", "username": username, "password": password})
        require_ok(recv_json(secured), "登录")
        return secured
    except BaseException:
        if secured is not None:
            secured.close()
        else:
            raw.close()
        raise


def list_remote_files(sock: ssl.SSLSocket) -> list[dict]:
    files: list[dict] = []
    cursor = None
    while True:
        request = {"op": "list"}
        if cursor is not None:
            request["cursor"] = cursor
        send_json(sock, request)
        response = require_ok(recv_json(sock), "刷新文件列表")
        batch = response.get("files")
        if not isinstance(batch, list):
            raise ProtocolError("server returned an invalid file list")
        files.extend(batch)
        cursor = response.get("next_cursor")
        if not cursor:
            return files


def upload_file(
    sock: ssl.SSLSocket,
    local_path: Path,
    progress: Callable[[str, int, int], None] | None = None,
) -> dict:
    if not local_path.is_file():
        raise OSError(f"找不到本地文件：{local_path}")
    size = local_path.stat().st_size
    if not valid_size(size, MAX_FILE_SIZE):
        raise RemoteError(f"文件大小需在 0 至 {format_size(MAX_FILE_SIZE)} 之间。")

    digest = hashlib.sha256()
    hashed = 0
    with local_path.open("rb") as stream:
        while block := stream.read(CHUNK_SIZE):
            digest.update(block)
            hashed += len(block)
            if progress is not None:
                progress("校验本地文件", hashed, size)
    expected = digest.hexdigest()
    send_json(sock, {"op": "upload", "name": local_path.name, "size": size, "sha256": expected})
    require_ok(recv_json(sock), "准备上传")

    deadline = time.monotonic() + 120 + size / (128 * 1024)
    with local_path.open("rb") as stream:
        send_stream(
            sock,
            stream,
            size,
            deadline=deadline,
            progress=(lambda amount: progress("正在上传", amount, size)) if progress else None,
        )
    response = require_ok(recv_json(sock), "上传")
    return {"name": response.get("name", local_path.name), "size": response.get("size", size), "sha256": expected}


def download_file(
    sock: ssl.SSLSocket,
    remote_name: str,
    destination: Path,
    progress: Callable[[str, int, int], None] | None = None,
) -> dict:
    send_json(sock, {"op": "download", "name": remote_name})
    response = require_ok(recv_json(sock), "下载")
    size = response.get("size")
    expected = response.get("sha256")
    if (
        not valid_size(size, MAX_FILE_SIZE)
        or not isinstance(expected, str)
        or not re.fullmatch(r"[0-9a-f]{64}", expected)
    ):
        raise ProtocolError("server returned invalid download metadata")

    destination = destination.expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".part", dir=destination.parent
    )
    try:
        deadline = time.monotonic() + 120 + size / (128 * 1024)
        with os.fdopen(descriptor, "wb") as stream:
            actual = recv_stream(
                sock,
                stream,
                size,
                deadline=deadline,
                progress=(lambda amount: progress("正在下载", amount, size)) if progress else None,
            )
            stream.flush()
            os.fsync(stream.fileno())
        if actual != expected:
            raise ProtocolError("下载文件的 SHA-256 校验失败")
        os.replace(temporary, destination)
        return {"name": remote_name, "size": size, "sha256": actual, "destination": destination}
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def delete_file(sock: ssl.SSLSocket, remote_name: str) -> dict:
    send_json(sock, {"op": "delete", "name": remote_name})
    response = require_ok(recv_json(sock), "删除")
    return {"name": response.get("name", remote_name), "size": response.get("size", 0)}


class SecureFileTransferApp(tk.Tk):
    BG = "#F5F3F8"
    PURPLE = "#4A185B"
    ACCENT = "#7A2B87"
    TEXT = "#24212A"
    MUTED = "#746D7A"
    BORDER = "#E3DDE8"
    WHITE = "#FFFFFF"

    def __init__(self) -> None:
        super().__init__()
        self.title("安全文件传输 · Secure File Transfer")
        self.geometry("1120x740")
        self.minsize(980, 650)
        self.configure(bg=self.BG)

        self.events: queue.Queue[tuple] = queue.Queue()
        self.sock: ssl.SSLSocket | None = None
        self.username: str | None = None
        self.files: list[dict] = []
        self.busy = False
        self._closing = False
        self.status_var = tk.StringVar(value="填写连接信息后登录。文件传输使用 TLS 和 SHA-256 校验。")
        self.count_var = tk.StringVar(value="0 个文件")
        self.progress_var = tk.StringVar(value="就绪")

        self._configure_styles()
        self._build_layout()
        self._apply_states()
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.after(100, self._poll_events)

    def _configure_styles(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TLabel", background=self.WHITE, foreground=self.TEXT, font=("Microsoft YaHei UI", 10))
        style.configure("TFrame", background=self.WHITE)
        style.configure("Sidebar.TFrame", background=self.BG)
        style.configure("Muted.TLabel", background=self.WHITE, foreground=self.MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("SidebarMuted.TLabel", background=self.BG, foreground=self.MUTED, font=("Microsoft YaHei UI", 9))
        style.configure("Title.TLabel", background=self.PURPLE, foreground=self.WHITE, font=("Microsoft YaHei UI", 20, "bold"))
        style.configure("Subtitle.TLabel", background=self.PURPLE, foreground="#E9DDED", font=("Microsoft YaHei UI", 9))
        style.configure("CardTitle.TLabel", background=self.WHITE, foreground=self.PURPLE, font=("Microsoft YaHei UI", 12, "bold"))
        style.configure("SidebarTitle.TLabel", background=self.BG, foreground=self.PURPLE, font=("Microsoft YaHei UI", 12, "bold"))
        style.configure("Primary.TButton", font=("Microsoft YaHei UI", 10, "bold"), padding=(12, 8),
                        background=self.ACCENT, foreground=self.WHITE)
        style.map("Primary.TButton", background=[("disabled", "#B8AABD"), ("active", "#642170")],
                  foreground=[("disabled", "#F6F3F7")])
        style.configure("TButton", font=("Microsoft YaHei UI", 9), padding=(9, 6))
        style.configure("Treeview", font=("Microsoft YaHei UI", 10), rowheight=32,
                        background=self.WHITE, fieldbackground=self.WHITE, foreground=self.TEXT)
        style.configure("Treeview.Heading", font=("Microsoft YaHei UI", 9, "bold"),
                        background="#F1EDF4", foreground=self.PURPLE, padding=(8, 9))
        style.configure("Horizontal.TProgressbar", troughcolor="#ECE7F0", background=self.ACCENT, thickness=10)

    def _build_layout(self) -> None:
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        header = tk.Frame(self, bg=self.PURPLE, height=94)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        tk.Label(header, text="安全文件传输", bg=self.PURPLE, fg=self.WHITE,
                 font=("Microsoft YaHei UI", 20, "bold"), anchor="w").grid(row=0, column=0, sticky="sw", padx=28, pady=(10, 37))
        tk.Label(header, text="TLS 1.2+  ·  双向证书认证  ·  SHA-256 完整性校验", bg=self.PURPLE, fg="#E9DDED",
                 font=("Microsoft YaHei UI", 9), anchor="w").grid(row=0, column=0, sticky="sw", padx=30, pady=(0, 14))
        tk.Label(header, text="SFT", bg=self.PURPLE, fg="#E8D9ED", font=("Segoe UI", 15, "bold")).grid(row=0, column=1, padx=28, sticky="e")
        header.columnconfigure(0, weight=1)

        content = tk.Frame(self, bg=self.BG)
        content.grid(row=1, column=0, sticky="nsew", padx=20, pady=18)
        content.columnconfigure(0, minsize=330)
        content.columnconfigure(1, weight=1)
        content.rowconfigure(0, weight=1)

        self._build_connection_card(content)
        self._build_file_card(content)
        self._build_status_bar()

    def _build_connection_card(self, parent: tk.Widget) -> None:
        card = tk.Frame(parent, bg=self.BG, highlightbackground=self.BORDER, highlightthickness=1)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 14))
        card.columnconfigure(0, weight=1)
        ttk.Label(card, text="连接与身份验证", style="SidebarTitle.TLabel").grid(row=0, column=0, sticky="w", padx=18, pady=(17, 5))
        ttk.Label(card, text="服务器地址", style="SidebarMuted.TLabel").grid(row=1, column=0, sticky="w", padx=18, pady=(12, 3))

        host_port = ttk.Frame(card, style="Sidebar.TFrame")
        host_port.grid(row=2, column=0, sticky="ew", padx=18)
        host_port.columnconfigure(0, weight=1)
        host_port.columnconfigure(1, minsize=85)
        self.host_entry = ttk.Entry(host_port)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.grid(row=0, column=0, sticky="ew", padx=(0, 8), ipady=5)
        self.port_entry = ttk.Entry(host_port, width=8)
        self.port_entry.insert(0, "9443")
        self.port_entry.grid(row=0, column=1, sticky="ew", ipady=5)
        self.connection_widgets: list[tk.Widget] = [self.host_entry, self.port_entry]

        ttk.Label(card, text="用户名", style="SidebarMuted.TLabel").grid(row=3, column=0, sticky="w", padx=18, pady=(12, 3))
        self.username_entry = ttk.Entry(card)
        self.username_entry.grid(row=4, column=0, sticky="ew", padx=18, ipady=5)
        self.connection_widgets.append(self.username_entry)

        ttk.Label(card, text="密码", style="SidebarMuted.TLabel").grid(row=5, column=0, sticky="w", padx=18, pady=(12, 3))
        self.password_entry = ttk.Entry(card, show="●")
        self.password_entry.grid(row=6, column=0, sticky="ew", padx=18, ipady=5)
        self.connection_widgets.append(self.password_entry)

        ttk.Separator(card).grid(row=7, column=0, sticky="ew", padx=18, pady=17)
        ttk.Label(card, text="证书设置", style="SidebarTitle.TLabel").grid(row=8, column=0, sticky="w", padx=18, pady=(0, 2))
        ttk.Label(card, text="本机演示默认使用项目 certs/mtls 目录。", style="SidebarMuted.TLabel").grid(row=9, column=0, sticky="w", padx=18, pady=(2, 8))

        self.ca_entry = self._certificate_row(card, 10, "信任 CA", DEFAULT_CA_CERT, "CA certificate")
        self.client_cert_entry = self._certificate_row(card, 11, "客户端证书", DEFAULT_CLIENT_CERT, "Client certificate")
        self.client_key_entry = self._certificate_row(card, 12, "客户端私钥", DEFAULT_CLIENT_KEY, "Client private key", key=True)

        self.login_button = ttk.Button(card, text="连接并登录", style="Primary.TButton", command=self._connect)
        self.login_button.grid(row=13, column=0, sticky="ew", padx=18, pady=(17, 8))
        self.logout_button = ttk.Button(card, text="退出登录", command=self._logout)
        self.logout_button.grid(row=14, column=0, sticky="ew", padx=18, pady=(0, 17))
        self.connection_widgets.extend([self.ca_entry, self.client_cert_entry, self.client_key_entry])
        self.connection_widgets.extend(self._certificate_buttons)

    def _certificate_row(self, parent: tk.Widget, row: int, label: str, value: Path, title: str, key: bool = False) -> ttk.Entry:
        if not hasattr(self, "_certificate_buttons"):
            self._certificate_buttons: list[ttk.Button] = []
        box = ttk.Frame(parent, style="Sidebar.TFrame")
        box.grid(row=row, column=0, sticky="ew", padx=18, pady=4)
        box.columnconfigure(1, weight=1)
        ttk.Label(box, text=label, style="SidebarMuted.TLabel", width=10).grid(row=0, column=0, sticky="w", padx=(0, 5))
        entry = ttk.Entry(box, font=("Segoe UI", 8), width=18)
        entry.insert(0, str(value))
        entry.grid(row=0, column=1, sticky="ew", ipady=4, padx=(0, 6))
        button = ttk.Button(box, text="浏览", width=7, command=lambda: self._browse_certificate(entry, title, key))
        button.grid(row=0, column=2, sticky="e")
        self._certificate_buttons.append(button)
        return entry

    def _browse_certificate(self, entry: ttk.Entry, title: str, key: bool) -> None:
        path = filedialog.askopenfilename(
            title=f"选择{title}",
            filetypes=[("PEM 证书或私钥", "*.pem *.key"), ("所有文件", "*.*")],
            initialdir=str(CERT_DIR if CERT_DIR.exists() else PROJECT_DIR),
        )
        if path:
            entry.delete(0, tk.END)
            entry.insert(0, path)

    def _build_file_card(self, parent: tk.Widget) -> None:
        card = tk.Frame(parent, bg=self.WHITE, highlightbackground=self.BORDER, highlightthickness=1)
        card.grid(row=0, column=1, sticky="nsew")
        card.columnconfigure(0, weight=1)
        card.rowconfigure(2, weight=1)

        heading = tk.Frame(card, bg=self.WHITE)
        heading.grid(row=0, column=0, sticky="ew", padx=20, pady=(18, 9))
        heading.columnconfigure(0, weight=1)
        ttk.Label(heading, text="我的远端文件", style="CardTitle.TLabel").grid(row=0, column=0, sticky="w")
        ttk.Label(heading, textvariable=self.count_var).grid(row=0, column=1, sticky="e")
        ttk.Label(card, text="选择本地文件后即可上传；下载会先校验 SHA-256 再保存。", style="Muted.TLabel").grid(row=1, column=0, sticky="w", padx=20, pady=(0, 10))

        table_box = tk.Frame(card, bg=self.WHITE)
        table_box.grid(row=2, column=0, sticky="nsew", padx=20)
        table_box.rowconfigure(0, weight=1)
        table_box.columnconfigure(0, weight=1)
        self.tree = ttk.Treeview(table_box, columns=("name", "size"), show="headings", selectmode="browse")
        self.tree.heading("name", text="文件名", anchor="w")
        self.tree.heading("size", text="大小", anchor="e")
        self.tree.column("name", anchor="w", width=430, stretch=True)
        self.tree.column("size", anchor="e", width=115, stretch=False)
        self.tree.grid(row=0, column=0, sticky="nsew")
        scrollbar = ttk.Scrollbar(table_box, orient="vertical", command=self.tree.yview)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.bind("<Double-1>", lambda _event: self._download_selected())

        actions = ttk.Frame(card)
        actions.grid(row=3, column=0, sticky="ew", padx=20, pady=15)
        actions.columnconfigure(0, weight=1)
        self.refresh_button = ttk.Button(actions, text="刷新列表", command=self._refresh)
        self.refresh_button.grid(row=0, column=0, sticky="w")
        self.ping_button = ttk.Button(actions, text="测试长连接", command=self._ping)
        self.ping_button.grid(row=0, column=1, sticky="e", padx=(0, 8))
        self.download_button = ttk.Button(actions, text="下载所选", command=self._download_selected)
        self.download_button.grid(row=0, column=2, sticky="e", padx=(0, 8))
        self.delete_button = ttk.Button(actions, text="删除所选", command=self._delete_selected)
        self.delete_button.grid(row=0, column=3, sticky="e", padx=(0, 8))
        self.upload_button = ttk.Button(actions, text="选择文件上传", style="Primary.TButton", command=self._choose_upload)
        self.upload_button.grid(row=0, column=4, sticky="e")

    def _build_status_bar(self) -> None:
        bar = tk.Frame(self, bg=self.WHITE, highlightbackground=self.BORDER, highlightthickness=1)
        bar.grid(row=2, column=0, sticky="ew", padx=20, pady=(0, 16))
        bar.columnconfigure(0, weight=1)
        tk.Label(bar, textvariable=self.status_var, bg=self.WHITE, fg=self.TEXT,
                 font=("Microsoft YaHei UI", 9), anchor="w").grid(row=0, column=0, sticky="ew", padx=15, pady=10)
        ttk.Label(bar, textvariable=self.progress_var, style="Muted.TLabel").grid(row=0, column=1, padx=(6, 8))
        self.progress = ttk.Progressbar(bar, orient="horizontal", mode="determinate", length=170, maximum=100)
        self.progress.grid(row=0, column=2, padx=(0, 14), pady=8)

    def _apply_states(self) -> None:
        connected = self.sock is not None
        field_state = "disabled" if connected or self.busy else "normal"
        for widget in self.connection_widgets:
            try:
                widget.configure(state=field_state)
            except tk.TclError:
                pass
        
        # 登录/退出按钮：使用grid_remove/grid来显示/隐藏，而不是禁用
        if not connected and not self.busy:
            # 未连接：显示登录按钮，隐藏退出按钮
            self.login_button.grid()
            self.login_button.configure(state="normal")
            self.logout_button.grid_remove()
        elif connected and not self.busy:
            # 已连接：隐藏登录按钮，显示退出按钮
            self.login_button.grid_remove()
            self.logout_button.grid()
            self.logout_button.configure(state="normal")
        else:
            # 忙碌中：两个按钮都禁用但保持当前显示状态
            self.login_button.configure(state="disabled")
            self.logout_button.configure(state="disabled")
        
        action_state = "normal" if connected and not self.busy else "disabled"
        for button in (self.refresh_button, self.ping_button, self.download_button,
                       self.delete_button, self.upload_button):
            button.configure(state=action_state)

    def _connect(self) -> None:
        host = self.host_entry.get().strip()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        try:
            port = int(self.port_entry.get().strip())
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showerror("连接信息有误", "端口号需为 1 到 65535 之间的整数。", parent=self)
            return
        if not host or not username or not password:
            messagebox.showerror("连接信息不完整", "请填写服务器地址、用户名和密码。", parent=self)
            return
        def certificate_path(value: str) -> str:
            path = Path(value).expanduser()
            if not path.is_absolute():
                path = PROJECT_DIR / path
            return str(path.resolve())

        ca_cert = certificate_path(self.ca_entry.get().strip())
        client_cert = certificate_path(self.client_cert_entry.get().strip())
        client_key = certificate_path(self.client_key_entry.get().strip())

        def work() -> dict:
            connection = create_authenticated_connection(host, port, username, password, ca_cert, client_cert, client_key)
            try:
                files = list_remote_files(connection)
            except BaseException:
                connection.close()
                raise
            return {"kind": "connected", "sock": connection, "username": username, "files": files}

        self._start_job("正在建立经验证的 TLS 连接…", work)

    def _logout(self) -> None:
        """退出登录,断开连接并清理会话状态"""
        connection = self.sock
        if connection is None:
            return

        # 询问确认
        if not messagebox.askyesno(
            "确认退出",
            f"确定要退出登录吗？\n\n当前用户: {self.username}\n服务器: {self.host_entry.get()}:{self.port_entry.get()}",
            parent=self
        ):
            return

        def work() -> dict:
            try:
                # 向服务器发送退出请求
                send_json(connection, {"op": "quit"})
                recv_json(connection)
            except Exception:
                pass  # 即使服务器无响应也继续关闭
            finally:
                connection.close()
            return {"kind": "logged_out"}

        self._start_job("正在退出登录…", work)

    def _refresh(self) -> None:
        connection = self.sock
        if connection is None:
            return
        self._start_job("正在刷新文件列表…", lambda: {"kind": "files", "files": list_remote_files(connection)})

    def _ping(self) -> None:
        connection = self.sock
        if connection is None:
            return

        def work() -> dict:
            send_json(connection, {"op": "ping"})
            require_ok(recv_json(connection), "连接测试")
            return {"kind": "status", "message": "连接正常；当前 TLS 会话仍保持打开。"}

        self._start_job("正在测试长连接…", work)

    def _choose_upload(self) -> None:
        local = filedialog.askopenfilename(title="选择要上传的本地文件", filetypes=[("所有文件", "*.*")])
        if not local:
            return
        path = Path(local)
        if any(item.get("name") == path.name for item in self.files):
            if not messagebox.askyesno("确认覆盖", f"远端已存在“{path.name}”，上传后会以完整新文件替换。继续吗？", parent=self):
                return
        connection = self.sock
        if connection is None:
            return

        def work() -> dict:
            result = upload_file(connection, path, self._queue_progress)
            files = list_remote_files(connection)
            return {"kind": "files", "files": files,
                    "message": f"已上传 {result['name']}（{format_size(result['size'])}），SHA-256 校验通过。"}

        self._start_job(f"准备上传 {path.name}…", work)

    def _download_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("选择文件", "请先在远端文件列表中选择一个文件。", parent=self)
            return
        remote_name = str(self.tree.item(selected[0], "values")[0])
        destination = filedialog.asksaveasfilename(
            title="选择下载保存位置",
            initialfile=remote_name,
            filetypes=[("所有文件", "*.*")],
        )
        if not destination:
            return
        path = Path(destination)
        if path.exists() and not messagebox.askyesno("确认覆盖", f"本地已存在“{path.name}”，校验成功后会替换它。继续吗？", parent=self):
            return
        connection = self.sock
        if connection is None:
            return

        def work() -> dict:
            result = download_file(connection, remote_name, path, self._queue_progress)
            return {"kind": "status", "message": f"已下载到 {result['destination']}；SHA-256 校验通过。"}

        self._start_job(f"准备下载 {remote_name}…", work)

    def _delete_selected(self) -> None:
        """删除所选的远端文件（删除不可恢复，需二次确认）。"""
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("选择文件", "请先在远端文件列表中选择一个文件。", parent=self)
            return
        remote_name = str(self.tree.item(selected[0], "values")[0])
        if not messagebox.askyesno(
            "确认删除",
            f"确定要删除远端文件“{remote_name}”吗？\n\n此操作不可撤销，服务器上的文件将被永久移除。",
            icon="warning",
            default="no",
            parent=self,
        ):
            return
        connection = self.sock
        if connection is None:
            return

        def work() -> dict:
            result = delete_file(connection, remote_name)
            files = list_remote_files(connection)
            return {"kind": "files", "files": files,
                    "message": f"已删除 {result['name']}（释放 {format_size(result['size'])}）。"}

        self._start_job(f"正在删除 {remote_name}…", work)

    def _queue_progress(self, stage: str, current: int, total: int) -> None:
        self.events.put(("progress", stage, current, total))

    def _start_job(self, message: str, work) -> None:
        if self.busy:
            return
        self.busy = True
        self.status_var.set(message)
        self.progress_var.set("处理中")
        self.progress.configure(maximum=100, value=0)
        self._apply_states()

        def run() -> None:
            try:
                result = work()
            except BaseException as exc:
                self.events.put(("error", exc))
            else:
                self.events.put(("done", result))

        threading.Thread(target=run, name="sft-network-operation", daemon=True).start()

    def _poll_events(self) -> None:
        if self._closing:
            return
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "progress":
                    _, stage, current, total = event
                    self.progress.configure(maximum=max(total, 1), value=current)
                    self.progress_var.set(f"{stage} · {format_size(current)} / {format_size(total)}")
                elif kind == "done":
                    self._handle_done(event[1])
                elif kind == "error":
                    self._handle_error(event[1])
        except queue.Empty:
            pass
        self.after(100, self._poll_events)

    def _handle_done(self, result: dict) -> None:
        kind = result.get("kind")
        self.busy = False
        if kind == "connected":
            self.sock = result["sock"]
            self.username = result["username"]
            self.password_entry.delete(0, tk.END)
            self.files = result["files"]
            self._render_files()
            self.status_var.set(f"已以 {self.username} 登录；TLS 证书已验证，长连接已建立。")
        elif kind == "logged_out":
            # 退出登录时清理所有会话状态
            self.sock = None
            self.username = None
            self.files = []
            self._render_files()
            self.password_entry.delete(0, tk.END)  # 清空密码输入框
            self.status_var.set("已退出登录。连接已安全断开。")
            messagebox.showinfo("退出成功", "您已安全退出登录。", parent=self)
        elif kind == "disconnected":
            # 兼容旧的断开连接逻辑
            self.sock = None
            self.username = None
            self.files = []
            self._render_files()
            self.status_var.set("连接已安全断开。")
        elif kind == "files":
            self.files = result["files"]
            self._render_files()
            self.status_var.set(result.get("message", f"文件列表已更新，共 {len(self.files)} 个文件。"))
        elif kind == "status":
            self.status_var.set(result["message"])
        self.progress_var.set("就绪")
        self.progress.configure(maximum=100, value=0)
        self._apply_states()

    def _handle_error(self, error: BaseException) -> None:
        self.busy = False
        if self.sock is not None and not isinstance(error, RemoteError):
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
            self.username = None
            # 连接中断时清空文件列表
            self.files = []
            self._render_files()
            self.status_var.set("连接中断，请重新登录。")
        else:
            self.status_var.set(f"操作未完成：{error}")
        self.progress_var.set("就绪")
        self.progress.configure(maximum=100, value=0)
        self._apply_states()
        messagebox.showerror("操作未完成", str(error), parent=self)

    def _render_files(self) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        for entry in self.files:
            name = entry.get("name", "")
            size = entry.get("size", 0)
            if isinstance(name, str) and isinstance(size, int):
                self.tree.insert("", tk.END, values=(name, format_size(size)))
        self.count_var.set(f"{len(self.files)} 个文件")

    def _on_close(self) -> None:
        if self.busy:
            if not messagebox.askyesno("正在传输", "关闭窗口会中断当前操作。确定退出吗？", parent=self):
                return
        
        # 如果还在登录状态,提示用户
        if self.sock is not None:
            if not messagebox.askyesno(
                "确认退出",
                f"您当前已登录为 {self.username}。\n关闭窗口将断开连接。\n\n确定要退出吗？",
                parent=self
            ):
                return
        
        self._closing = True
        if self.sock is not None:
            try:
                # 尝试优雅地通知服务器退出
                send_json(self.sock, {"op": "quit"})
            except Exception:
                pass  # 忽略退出时的错误
            finally:
                try:
                    self.sock.close()
                except OSError:
                    pass
                self.sock = None
        self.destroy()


def main() -> None:
    app = SecureFileTransferApp()
    app.mainloop()


if __name__ == "__main__":
    main()
