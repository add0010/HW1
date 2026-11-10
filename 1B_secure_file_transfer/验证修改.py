#!/usr/bin/env python3
"""验证 client_gui.py 是否包含退出登录功能"""

import sys
from pathlib import Path

def verify_modifications():
    client_file = Path(__file__).parent / "client_gui.py"
    
    if not client_file.exists():
        print("❌ 找不到 client_gui.py")
        return False
    
    content = client_file.read_text(encoding='utf-8')
    
    checks = {
        "logout_button 定义": "self.logout_button = ttk.Button",
        "_logout 方法": "def _logout(self)",
        "logged_out 处理": 'elif kind == "logged_out"',
        "密码清空": "self.password_entry.delete(0, tk.END)",
        "退出登录文字": 'text="退出登录"',
    }
    
    print("=" * 60)
    print("client_gui.py 修改验证")
    print("=" * 60)
    print(f"文件路径: {client_file}")
    print(f"文件大小: {client_file.stat().st_size} bytes")
    print(f"修改时间: {client_file.stat().st_mtime}")
    print()
    
    all_pass = True
    for name, pattern in checks.items():
        if pattern in content:
            print(f"✓ {name}")
        else:
            print(f"✗ {name}")
            all_pass = False
    
    print()
    if all_pass:
        print("🎉 所有修改都已正确应用!")
        print()
        print("⚠️  如果GUI界面没有变化，请：")
        print("   1. 关闭当前运行的客户端程序")
        print("   2. 重新运行: python client_gui.py")
        print()
        print("   Python会缓存已导入的模块，必须重启程序才能看到修改！")
        return True
    else:
        print("❌ 部分修改缺失，请检查代码!")
        return False

if __name__ == "__main__":
    success = verify_modifications()
    sys.exit(0 if success else 1)
