@echo off
chcp 65001 >nul
REM SecureFileTransfer 一键初始化脚本

echo ========================================
echo SecureFileTransfer 一键初始化
echo ========================================
echo.
echo 本脚本将完成以下操作:
echo   1. 检查Python环境
echo   2. 安装依赖包
echo   3. 生成TLS证书
echo   4. 创建必要目录
echo   5. 验证配置
echo.
pause
echo.

cd /d "%~dp0\.."

REM ===== 1. 检查Python =====
echo [1/5] 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo [×] 未找到Python，请先安装Python 3.7+
    echo     下载: https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2" %%v in ('python --version 2^>^&1') do set PY_VER=%%v
echo [√] Python版本: %PY_VER%
echo.

REM ===== 2. 安装依赖 =====
echo [2/5] 安装Python依赖包...

if exist requirements.txt (
    echo 从 requirements.txt 安装...
    python -m pip install -r requirements.txt -q
) else (
    echo 安装基础依赖...
    python -m pip install cryptography PyQt5 -q
)

if errorlevel 1 (
    echo [×] 依赖安装失败
    pause
    exit /b 1
)
echo [√] 依赖安装完成
echo.

REM ===== 3. 生成证书 =====
echo [3/5] 生成TLS证书...

REM 检查证书是否已存在
if exist "certs\mtls\ca-cert.pem" (
    echo [!] 证书已存在，跳过生成
    echo     如需重新生成，请删除 certs\mtls 目录
) else (
    echo 调用证书生成脚本...
    cd scripts
    call generate_certs_simple.bat
    if errorlevel 1 (
        echo [×] 证书生成失败
        cd ..
        pause
        exit /b 1
    )
    cd ..
    echo [√] 证书生成完成
)
echo.

REM ===== 4. 创建目录 =====
echo [4/5] 创建必要目录...

if not exist storage mkdir storage
if not exist storage\uploads mkdir storage\uploads
if not exist storage\downloads mkdir storage\downloads

echo [√] 目录结构:
echo     storage\
echo       uploads\    (服务器接收文件)
echo       downloads\  (客户端下载文件)
echo.

REM ===== 5. 验证配置 =====
echo [5/5] 验证配置...

set OK=1

if not exist "certs\mtls\ca-cert.pem" (
    echo [×] 缺少: certs\mtls\ca-cert.pem
    set OK=0
)
if not exist "certs\mtls\server-cert.pem" (
    echo [×] 缺少: certs\mtls\server-cert.pem
    set OK=0
)
if not exist "certs\mtls\server-key.pem" (
    echo [×] 缺少: certs\mtls\server-key.pem
    set OK=0
)
if not exist "certs\mtls\client-cert.pem" (
    echo [×] 缺少: certs\mtls\client-cert.pem
    set OK=0
)
if not exist "certs\mtls\client-key.pem" (
    echo [×] 缺少: certs\mtls\client-key.pem
    set OK=0
)
if not exist "server.py" (
    echo [×] 缺少: server.py
    set OK=0
)
if not exist "client.py" (
    echo [×] 缺少: client.py
    set OK=0
)
if not exist "protocol.py" (
    echo [×] 缺少: protocol.py
    set OK=0
)

if %OK%==0 (
    echo.
    echo [×] 配置验证失败，缺少必要文件
    pause
    exit /b 1
)

echo [√] 所有配置文件完整
echo.

REM ===== 完成 =====
echo ========================================
echo 初始化完成！
echo ========================================
echo.
echo 现在可以运行:
echo.
echo   启动服务器:
echo     python server.py
echo.
echo   启动客户端 (命令行):
echo     python client.py
echo.
echo   启动客户端 (图形界面):
echo     python client_gui.py
echo.
echo ========================================
echo.
echo 测试账户:
echo   用户名: alice   密码: alice123
echo   用户名: bob     密码: bob456
echo.
echo ========================================
echo.

REM 询问是否启动服务器
set /p "start_server=是否现在启动服务器? (y/N): "
if /i "%start_server%"=="y" (
    echo.
    echo 启动服务器...
    start cmd /k "python server.py"
    timeout /t 2 >nul
    
    echo.
    set /p "start_client=是否启动客户端GUI? (y/N): "
    if /i "!start_client!"=="y" (
        echo 启动客户端...
        start cmd /k "python client_gui.py"
    )
)

echo.
echo 初始化脚本结束
pause
