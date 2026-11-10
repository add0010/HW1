# 安全文件传输软件（实验 1B）

这是一个基于 Python 标准库的安全文件传输项目，包含 Tkinter 图形客户端、命令行客户端和支持并发连接的服务端。图形界面支持浏览远端文件、选择并上传本地文件、下载远端文件、显示传输进度，以及测试长连接。

## 环境

- Windows 10/11 或其他带 Tkinter 的桌面系统
- Python 3.10 或更高版本
- Windows PowerShell 7（生成本机演示证书；Linux/macOS 使用 OpenSSL 脚本）
- Python 代码不需要安装第三方包

## 快速启动（Windows）

在 PowerShell 中进入项目目录：

```powershell
Set-Location D:\workspace\projects\python\hw\hw4\1B_secure_file_transfer
```

首次使用时生成 CA、服务端和客户端演示证书，并创建两个不同用户：

```powershell
pwsh -NoProfile -ExecutionPolicy Bypass -File .\scripts\generate_demo_cert.ps1
py server.py add-user student_a
py server.py add-user student_b
```

添加用户时输入至少 12 个字符的密码。用户名须为 1–32 位 ASCII 字母、数字、点、下划线或连字符；如果用户名已存在，请换一个。

在第一个 PowerShell 窗口启动服务端：

```powershell
py server.py serve --host 0.0.0.0 --port 9443
```

另开窗口启动桌面客户端：

```powershell
py client_gui.py
```

本机演示默认连接 `127.0.0.1:9443`。填写用户名和密码后点击“连接并登录”。证书输入框默认指向 `certs\mtls` 中生成的 CA 证书、客户端证书和客户端私钥。

## 图形界面操作

1. 点击“连接并登录”，验证 TLS 双向证书和账号密码。
2. 点击“选择文件上传”，在系统文件对话框中选取本地文件；同名远端文件会先询问是否覆盖。
3. 上传结束后文件列表自动刷新，并显示 SHA-256 校验完成。
4. 选中远端文件后点击“下载所选”，选择本地保存路径；也可以双击远端文件。
5. 点击“测试长连接”确认操作完成后连接仍保持打开；完成后点击“断开连接”。

同一台电脑可再启动一个 `py client_gui.py` 窗口，使用 `student_b` 登录以演示并发和用户目录隔离。命令行客户端仍可通过 `py client.py --help` 查看参数。

## 录屏流程

请按[《使用与录屏指南》](使用与录屏指南.md)展示编译、部署、登录、上传、下载、哈希对比和并发访问。

## 安全与部署说明

服务端要求客户端提供受信任的客户端证书；客户端验证服务端证书链和主机名。账号密码只在 TLS 通道内传输，服务端保存 PBKDF2-HMAC-SHA256 派生值。单文件上限、单用户配额、并发连接数和登录失败速率均有边界限制。演示私钥、用户数据与用户文件已加入 `.gitignore`，不要把演示私钥提交到公开仓库。

本项目定位为课程演示。部署到其他电脑时，应为实际服务器 DNS 名称/IP 签发证书，并通过可信渠道分发 CA 证书和客户端证书材料；服务端还应运行在受限系统账号下，并设置 Windows 文件 ACL。
