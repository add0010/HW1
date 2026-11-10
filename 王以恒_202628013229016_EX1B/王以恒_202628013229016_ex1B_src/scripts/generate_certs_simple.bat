@echo off
chcp 65001 >nul
REM 简化版证书生成脚本 - 自动检测OpenSSL

setlocal EnableDelayedExpansion

echo ========================================
echo SecureFileTransfer 证书生成工具
echo ========================================
echo.

REM 查找 OpenSSL
set "OPENSSL="

REM 检查常见安装位置
set "PATHS=D:\software\git\Git\usr\bin\openssl.exe"
set "PATHS=%PATHS%;C:\Program Files\Git\usr\bin\openssl.exe"
set "PATHS=%PATHS%;C:\Program Files (x86)\Git\usr\bin\openssl.exe"

for %%P in (%PATHS%) do (
    if exist "%%~P" (
        set "OPENSSL=%%~P"
        echo [√] 找到 OpenSSL: !OPENSSL!
        goto :found_openssl
    )
)

REM 尝试从PATH查找
where openssl >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    for /f "tokens=*" %%i in ('where openssl') do (
        set "OPENSSL=%%i"
        echo [√] 找到 OpenSSL: !OPENSSL!
        goto :found_openssl
    )
)

REM 未找到OpenSSL
echo [×] 未找到 OpenSSL
echo.
echo 请安装以下之一:
echo 1. Git for Windows (包含OpenSSL): https://git-scm.com/download/win
echo 2. OpenSSL: https://slproweb.com/products/Win32OpenSSL.html
echo.
pause
exit /b 1

:found_openssl
echo.

REM 设置输出目录
cd /d "%~dp0"
set "OUTPUT_DIR=..\certs\mtls"

if not exist "%OUTPUT_DIR%" (
    mkdir "%OUTPUT_DIR%"
    echo [√] 创建目录: %OUTPUT_DIR%
) else (
    echo [√] 输出目录: %OUTPUT_DIR%
)
echo.

REM 检查现有证书
if exist "%OUTPUT_DIR%\ca-cert.pem" (
    echo [!] 警告: 证书文件已存在
    set /p "overwrite=是否覆盖? (y/N): "
    if /i not "!overwrite!"=="y" (
        echo 已取消
        pause
        exit /b 0
    )
    del /Q "%OUTPUT_DIR%\*.pem" 2>nul
    echo [√] 已清理旧证书
    echo.
)

echo ========================================
echo 开始生成证书...
echo ========================================
echo.

REM 1. 生成CA证书
echo [1/3] 生成 CA 根证书...
"%OPENSSL%" req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 ^
    -keyout "%OUTPUT_DIR%\ca-key.pem" ^
    -out "%OUTPUT_DIR%\ca-cert.pem" ^
    -subj "/CN=SecureFileTransfer Demo CA" ^
    -addext "basicConstraints=critical,CA:TRUE" ^
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>nul

if errorlevel 1 goto :error
echo       √ ca-cert.pem
echo       √ ca-key.pem
echo.

REM 2. 生成服务器证书
echo [2/3] 生成服务器证书...

REM 创建服务器扩展配置
(
echo basicConstraints=critical,CA:FALSE
echo keyUsage=critical,digitalSignature,keyEncipherment
echo extendedKeyUsage=serverAuth
echo subjectAltName=DNS:localhost,IP:127.0.0.1
) > "%OUTPUT_DIR%\server_ext.cnf"

"%OPENSSL%" req -newkey rsa:3072 -nodes -sha256 ^
    -keyout "%OUTPUT_DIR%\server-key.pem" ^
    -out "%OUTPUT_DIR%\server.csr" ^
    -subj "/CN=localhost" 2>nul

if errorlevel 1 goto :error

"%OPENSSL%" x509 -req -in "%OUTPUT_DIR%\server.csr" ^
    -CA "%OUTPUT_DIR%\ca-cert.pem" ^
    -CAkey "%OUTPUT_DIR%\ca-key.pem" ^
    -CAcreateserial -days 365 -sha256 ^
    -out "%OUTPUT_DIR%\server-cert.pem" ^
    -extfile "%OUTPUT_DIR%\server_ext.cnf" 2>nul

if errorlevel 1 goto :error
echo       √ server-cert.pem
echo       √ server-key.pem
echo.

REM 3. 生成客户端证书
echo [3/3] 生成客户端证书...

REM 创建客户端扩展配置
(
echo basicConstraints=critical,CA:FALSE
echo keyUsage=critical,digitalSignature,keyEncipherment
echo extendedKeyUsage=clientAuth
) > "%OUTPUT_DIR%\client_ext.cnf"

"%OPENSSL%" req -newkey rsa:3072 -nodes -sha256 ^
    -keyout "%OUTPUT_DIR%\client-key.pem" ^
    -out "%OUTPUT_DIR%\client.csr" ^
    -subj "/CN=SecureFileTransfer Demo Client" 2>nul

if errorlevel 1 goto :error

"%OPENSSL%" x509 -req -in "%OUTPUT_DIR%\client.csr" ^
    -CA "%OUTPUT_DIR%\ca-cert.pem" ^
    -CAkey "%OUTPUT_DIR%\ca-key.pem" ^
    -CAcreateserial -days 365 -sha256 ^
    -out "%OUTPUT_DIR%\client-cert.pem" ^
    -extfile "%OUTPUT_DIR%\client_ext.cnf" 2>nul

if errorlevel 1 goto :error
echo       √ client-cert.pem
echo       √ client-key.pem
echo.

REM 清理临时文件
del /Q "%OUTPUT_DIR%\*.csr" 2>nul
del /Q "%OUTPUT_DIR%\*.cnf" 2>nul
del /Q "%OUTPUT_DIR%\*.srl" 2>nul

REM 成功
echo ========================================
echo 证书生成成功！
echo ========================================
echo.
echo 生成的文件:
dir /B "%OUTPUT_DIR%\*.pem" | findstr /V /C:"searching"
echo.
echo 使用说明:
echo   • CA证书 (ca-cert.pem): 服务器和客户端都需要信任
echo   • 服务器: server-cert.pem + server-key.pem
echo   • 客户端: client-cert.pem + client-key.pem
echo.
echo 安全提醒:
echo   ⚠ 私钥文件 (*-key.pem) 请妥善保管
echo   ⚠ 不要提交到 Git 仓库
echo   ⚠ 这些证书仅用于开发测试
echo.
echo ========================================
echo.
pause
exit /b 0

:error
echo.
echo ========================================
echo [×] 错误: 证书生成失败
echo ========================================
echo.
REM 清理失败的文件
del /Q "%OUTPUT_DIR%\*.pem" 2>nul
del /Q "%OUTPUT_DIR%\*.csr" 2>nul
del /Q "%OUTPUT_DIR%\*.cnf" 2>nul
del /Q "%OUTPUT_DIR%\*.srl" 2>nul
pause
exit /b 1
