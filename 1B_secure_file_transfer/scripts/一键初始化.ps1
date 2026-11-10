# SecureFileTransfer 一键初始化脚本 (PowerShell)
$ErrorActionPreference = "Stop"

function Write-Step {
    param([string]$Message)
    Write-Host $Message -ForegroundColor Cyan
}

function Write-Success {
    param([string]$Message)
    Write-Host "[√] $Message" -ForegroundColor Green
}

function Write-Error-Custom {
    param([string]$Message)
    Write-Host "[×] $Message" -ForegroundColor Red
}

function Write-Warning-Custom {
    param([string]$Message)
    Write-Host "[!] $Message" -ForegroundColor Yellow
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SecureFileTransfer 一键初始化" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "本脚本将完成以下操作:"
Write-Host "  1. 检查Python环境"
Write-Host "  2. 安装依赖包"
Write-Host "  3. 生成TLS证书"
Write-Host "  4. 创建必要目录"
Write-Host "  5. 验证配置"
Write-Host ""
Read-Host "按Enter继续"
Write-Host ""

# 切换到项目根目录
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir
Set-Location $projectRoot

try {
    # ===== 1. 检查Python =====
    Write-Step "[1/5] 检查Python环境..."
    
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
            Write-Success "Python版本: $($matches[1])"
        } else {
            throw "无法获取Python版本"
        }
    } catch {
        Write-Error-Custom "未找到Python，请先安装Python 3.7+"
        Write-Host "    下载: https://www.python.org/downloads/" -ForegroundColor Gray
        Read-Host "按Enter退出"
        exit 1
    }
    Write-Host ""

    # ===== 2. 安装依赖 =====
    Write-Step "[2/5] 安装Python依赖包..."
    
    if (Test-Path "requirements.txt") {
        Write-Host "从 requirements.txt 安装..." -ForegroundColor Gray
        python -m pip install -r requirements.txt -q
    } else {
        Write-Host "安装基础依赖..." -ForegroundColor Gray
        python -m pip install cryptography PyQt5 -q
    }
    
    if ($LASTEXITCODE -ne 0) {
        throw "依赖安装失败"
    }
    Write-Success "依赖安装完成"
    Write-Host ""

    # ===== 3. 生成证书 =====
    Write-Step "[3/5] 生成TLS证书..."
    
    if (Test-Path "certs\mtls\ca-cert.pem") {
        Write-Warning-Custom "证书已存在，跳过生成"
        Write-Host "    如需重新生成，请删除 certs\mtls 目录" -ForegroundColor Gray
    } else {
        Write-Host "调用证书生成脚本..." -ForegroundColor Gray
        
        $certScript = Join-Path $scriptDir "generate_certs_auto.ps1"
        if (Test-Path $certScript) {
            & $certScript
            if ($LASTEXITCODE -ne 0) {
                throw "证书生成失败"
            }
        } else {
            throw "找不到证书生成脚本: $certScript"
        }
        Write-Success "证书生成完成"
    }
    Write-Host ""

    # ===== 4. 创建目录 =====
    Write-Step "[4/5] 创建必要目录..."
    
    $dirs = @("storage", "storage\uploads", "storage\downloads")
    foreach ($dir in $dirs) {
        if (-not (Test-Path $dir)) {
            New-Item -ItemType Directory -Path $dir -Force | Out-Null
        }
    }
    
    Write-Success "目录结构:"
    Write-Host "    storage\" -ForegroundColor Gray
    Write-Host "      uploads\    (服务器接收文件)" -ForegroundColor Gray
    Write-Host "      downloads\  (客户端下载文件)" -ForegroundColor Gray
    Write-Host ""

    # ===== 5. 验证配置 =====
    Write-Step "[5/5] 验证配置..."
    
    $requiredFiles = @(
        "certs\mtls\ca-cert.pem",
        "certs\mtls\server-cert.pem",
        "certs\mtls\server-key.pem",
        "certs\mtls\client-cert.pem",
        "certs\mtls\client-key.pem",
        "server.py",
        "client.py",
        "protocol.py"
    )
    
    $allOk = $true
    foreach ($file in $requiredFiles) {
        if (-not (Test-Path $file)) {
            Write-Error-Custom "缺少: $file"
            $allOk = $false
        }
    }
    
    if (-not $allOk) {
        throw "配置验证失败，缺少必要文件"
    }
    
    Write-Success "所有配置文件完整"
    Write-Host ""

    # ===== 完成 =====
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "初始化完成！" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "现在可以运行:" -ForegroundColor White
    Write-Host ""
    Write-Host "  启动服务器:" -ForegroundColor Yellow
    Write-Host "    python server.py" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  启动客户端 (命令行):" -ForegroundColor Yellow
    Write-Host "    python client.py" -ForegroundColor Gray
    Write-Host ""
    Write-Host "  启动客户端 (图形界面):" -ForegroundColor Yellow
    Write-Host "    python client_gui.py" -ForegroundColor Gray
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""
    Write-Host "测试账户:" -ForegroundColor Yellow
    Write-Host "  用户名: alice   密码: alice123" -ForegroundColor Gray
    Write-Host "  用户名: bob     密码: bob456" -ForegroundColor Gray
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    # 询问是否启动服务器
    $startServer = Read-Host "是否现在启动服务器? (y/N)"
    if ($startServer -eq "y" -or $startServer -eq "Y") {
        Write-Host ""
        Write-Host "启动服务器..." -ForegroundColor Cyan
        Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; python server.py"
        Start-Sleep -Seconds 2
        
        $startClient = Read-Host "是否启动客户端GUI? (y/N)"
        if ($startClient -eq "y" -or $startClient -eq "Y") {
            Write-Host "启动客户端..." -ForegroundColor Cyan
            Start-Process powershell -ArgumentList "-NoExit", "-Command", "cd '$projectRoot'; python client_gui.py"
        }
    }

    Write-Host ""
    Write-Host "初始化脚本结束" -ForegroundColor Green

} catch {
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Red
    Write-Host "错误: $_" -ForegroundColor Red
    Write-Host "========================================" -ForegroundColor Red
    Write-Host ""
    Read-Host "按Enter退出"
    exit 1
}
