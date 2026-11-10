# 自动检测 OpenSSL 并生成双向 TLS 证书
# 兼容 Windows PowerShell 5.1+

$ErrorActionPreference = "Stop"

# 输出目录（绝对路径）
$SCRIPT_DIR = Split-Path -Parent $MyInvocation.MyCommand.Path
$OUTPUT_DIR = Join-Path $SCRIPT_DIR "..\certs\mtls"
$OUTPUT_DIR = [System.IO.Path]::GetFullPath($OUTPUT_DIR)

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SecureFileTransfer 证书生成工具" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# 自动检测 OpenSSL
$OPENSSL = $null
$possiblePaths = @(
    "D:\software\git\Git\usr\bin\openssl.exe",
    "C:\Program Files\Git\usr\bin\openssl.exe",
    "C:\Program Files (x86)\Git\usr\bin\openssl.exe",
    "${env:ProgramFiles}\Git\usr\bin\openssl.exe",
    "${env:ProgramFiles(x86)}\Git\usr\bin\openssl.exe"
)

# 检查预设路径
foreach ($path in $possiblePaths) {
    if (Test-Path $path) {
        $OPENSSL = $path
        Write-Host "[✓] 找到 OpenSSL: $OPENSSL" -ForegroundColor Green
        break
    }
}

# 尝试从系统 PATH 查找
if (-not $OPENSSL) {
    try {
        $opensslCmd = Get-Command openssl -ErrorAction Stop
        $OPENSSL = $opensslCmd.Source
        Write-Host "[✓] 找到 OpenSSL (系统PATH): $OPENSSL" -ForegroundColor Green
    } catch {
        # 未找到
    }
}

# 如果仍未找到，提示用户手动输入
if (-not $OPENSSL) {
    Write-Host "[×] 未找到 OpenSSL" -ForegroundColor Red
    Write-Host ""
    Write-Host "请手动输入 OpenSSL 可执行文件的完整路径:" -ForegroundColor Yellow
    Write-Host "通常位于: C:\Program Files\Git\usr\bin\openssl.exe" -ForegroundColor Gray
    Write-Host ""
    $manualPath = Read-Host "OpenSSL路径"
    
    if (Test-Path $manualPath) {
        $OPENSSL = $manualPath
        Write-Host "[✓] 使用: $OPENSSL" -ForegroundColor Green
    } else {
        Write-Host "[×] 路径无效: $manualPath" -ForegroundColor Red
        Write-Host ""
        Write-Host "解决方案:" -ForegroundColor Yellow
        Write-Host "1. 安装 Git for Windows (包含OpenSSL): https://git-scm.com/download/win" -ForegroundColor Gray
        Write-Host "2. 或安装 OpenSSL: https://slproweb.com/products/Win32OpenSSL.html" -ForegroundColor Gray
        exit 1
    }
}

Write-Host ""

# 创建输出目录
New-Item -ItemType Directory -Path $OUTPUT_DIR -Force | Out-Null
Write-Host "[✓] 输出目录: $OUTPUT_DIR" -ForegroundColor Green
Write-Host ""

# 检查是否已存在证书
if (Test-Path "$OUTPUT_DIR\ca-cert.pem") {
    Write-Host "[!] 警告: 证书文件已存在" -ForegroundColor Yellow
    Write-Host ""
    $choice = Read-Host "是否覆盖现有证书? (y/N)"
    if ($choice -ne "y" -and $choice -ne "Y") {
        Write-Host "已取消" -ForegroundColor Gray
        exit 0
    }
    # 删除旧证书
    Remove-Item "$OUTPUT_DIR\*.pem" -ErrorAction SilentlyContinue
    Write-Host "[✓] 已清理旧证书" -ForegroundColor Green
    Write-Host ""
}

# 开始生成证书
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "开始生成证书..." -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

try {
    # 1. 生成 CA 证书
    Write-Host "[1/3] 生成 CA 根证书..." -ForegroundColor Cyan
    $args = @(
        "req", "-x509", "-newkey", "rsa:3072", "-nodes", "-sha256", "-days", "3650",
        "-keyout", "$OUTPUT_DIR\ca-key.pem",
        "-out", "$OUTPUT_DIR\ca-cert.pem",
        "-subj", "/CN=SecureFileTransfer Demo CA",
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign"
    )
    & $OPENSSL @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "CA证书生成失败" }
    Write-Host "      ✓ ca-cert.pem" -ForegroundColor Green
    Write-Host "      ✓ ca-key.pem" -ForegroundColor Green
    Write-Host ""

    # 2. 生成服务器证书
    Write-Host "[2/3] 生成服务器证书..." -ForegroundColor Cyan
    
    # 创建服务器扩展配置
    $serverExt = @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
"@
    $serverExt | Out-File -Encoding ASCII -FilePath "$OUTPUT_DIR\server_ext.cnf"
    
    # 生成服务器私钥和CSR
    $args = @(
        "req", "-newkey", "rsa:3072", "-nodes", "-sha256",
        "-keyout", "$OUTPUT_DIR\server-key.pem",
        "-out", "$OUTPUT_DIR\server.csr",
        "-subj", "/CN=localhost"
    )
    & $OPENSSL @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "服务器CSR生成失败" }
    
    # 签署服务器证书
    $args = @(
        "x509", "-req", "-in", "$OUTPUT_DIR\server.csr",
        "-CA", "$OUTPUT_DIR\ca-cert.pem",
        "-CAkey", "$OUTPUT_DIR\ca-key.pem",
        "-CAcreateserial", "-days", "365", "-sha256",
        "-out", "$OUTPUT_DIR\server-cert.pem",
        "-extfile", "$OUTPUT_DIR\server_ext.cnf"
    )
    & $OPENSSL @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "服务器证书签名失败" }
    
    Write-Host "      ✓ server-cert.pem" -ForegroundColor Green
    Write-Host "      ✓ server-key.pem" -ForegroundColor Green
    Write-Host ""

    # 3. 生成客户端证书
    Write-Host "[3/3] 生成客户端证书..." -ForegroundColor Cyan
    
    # 创建客户端扩展配置
    $clientExt = @"
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
"@
    $clientExt | Out-File -Encoding ASCII -FilePath "$OUTPUT_DIR\client_ext.cnf"
    
    # 生成客户端私钥和CSR
    $args = @(
        "req", "-newkey", "rsa:3072", "-nodes", "-sha256",
        "-keyout", "$OUTPUT_DIR\client-key.pem",
        "-out", "$OUTPUT_DIR\client.csr",
        "-subj", "/CN=SecureFileTransfer Demo Client"
    )
    & $OPENSSL @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "客户端CSR生成失败" }
    
    # 签署客户端证书
    $args = @(
        "x509", "-req", "-in", "$OUTPUT_DIR\client.csr",
        "-CA", "$OUTPUT_DIR\ca-cert.pem",
        "-CAkey", "$OUTPUT_DIR\ca-key.pem",
        "-CAcreateserial", "-days", "365", "-sha256",
        "-out", "$OUTPUT_DIR\client-cert.pem",
        "-extfile", "$OUTPUT_DIR\client_ext.cnf"
    )
    & $OPENSSL @args 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "客户端证书签名失败" }
    
    Write-Host "      ✓ client-cert.pem" -ForegroundColor Green
    Write-Host "      ✓ client-key.pem" -ForegroundColor Green
    Write-Host ""

    # 清理临时文件
    Remove-Item "$OUTPUT_DIR\*.csr" -ErrorAction SilentlyContinue
    Remove-Item "$OUTPUT_DIR\*.cnf" -ErrorAction SilentlyContinue
    Remove-Item "$OUTPUT_DIR\*.srl" -ErrorAction SilentlyContinue

    # 验证证书
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "证书生成成功！" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "生成的文件:" -ForegroundColor White
    Get-ChildItem "$OUTPUT_DIR\*.pem" | ForEach-Object {
        $size = [Math]::Round($_.Length / 1KB, 2)
        Write-Host "  ✓ $($_.Name)" -NoNewline -ForegroundColor Green
        Write-Host " ($size KB)" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "使用说明:" -ForegroundColor Yellow
    Write-Host "  • CA证书 (ca-cert.pem): 服务器和客户端都需要信任" -ForegroundColor Gray
    Write-Host "  • 服务器: server-cert.pem + server-key.pem" -ForegroundColor Gray
    Write-Host "  • 客户端: client-cert.pem + client-key.pem" -ForegroundColor Gray
    Write-Host ""
    Write-Host "安全提醒:" -ForegroundColor Red
    Write-Host "  ⚠ 私钥文件 (*-key.pem) 请妥善保管" -ForegroundColor Gray
    Write-Host "  ⚠ 不要提交到 Git 仓库" -ForegroundColor Gray
    Write-Host "  ⚠ 这些证书仅用于开发测试" -ForegroundColor Gray
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green

} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "[×] 错误: $_" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    
    # 清理失败的文件
    Remove-Item "$OUTPUT_DIR\*.pem" -ErrorAction SilentlyContinue
    Remove-Item "$OUTPUT_DIR\*.csr" -ErrorAction SilentlyContinue
    Remove-Item "$OUTPUT_DIR\*.cnf" -ErrorAction SilentlyContinue
    Remove-Item "$OUTPUT_DIR\*.srl" -ErrorAction SilentlyContinue
    
    exit 1
}
