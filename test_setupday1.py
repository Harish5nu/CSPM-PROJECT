# test_setup.py
import os
import sys
import subprocess

print("=" * 50)
print("Day 1 Setup Verification - Windows")
print("=" * 50)

# Test 1: Python version
print(f"\n[1] Python version: {sys.version}")
if sys.version_info.major >= 3 and sys.version_info.minor >= 10:
    print("    ✅ Python 3.10+ found")
else:
    print("    ❌ Need Python 3.10 or higher")

# Test 2: Virtual environment
in_venv = hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
if in_venv:
    print("    ✅ Virtual environment active")
else:
    print("    ❌ Virtual environment NOT active. Run: venv\\Scripts\\activate")

# Test 3: Required packages
packages = ['boto3', 'pandas', 'streamlit', 'dotenv']
for pkg in packages:
    try:
        __import__(pkg)
        print(f"    ✅ {pkg} installed")
    except ImportError:
        print(f"    ❌ {pkg} missing. Run: pip install {pkg}")

# Test 4: .env file
if os.path.exists(".env"):
    print("    ✅ .env file exists")
    # Check if it has content
    if os.path.getsize(".env") > 0:
        print("    ✅ .env has content")
    else:
        print("    ❌ .env is empty - add your AWS credentials")
else:
    print("    ❌ .env file missing")

# Test 5: Folder structure
folders = ["src", "dashboard", "data", "scripts", "config", "tests"]
for folder in folders:
    if os.path.exists(folder):
        print(f"    ✅ {folder}/ exists")
    else:
        print(f"    ❌ {folder}/ missing")

# Test 6: Ollama (optional)
try:
    result = subprocess.run(['ollama', 'list'], capture_output=True, text=True)
    if result.returncode == 0:
        if 'llama3.2:1b' in result.stdout:
            print("    ✅ Ollama running with llama3.2:1b")
        else:
            print("    ⚠️ Ollama running but model not pulled. Run: ollama pull llama3.2:1b")
    else:
        print("    ❌ Ollama not found. Install from https://ollama.com")
except FileNotFoundError:
    print("    ❌ Ollama not installed")

print("\n" + "=" * 50)
print("Verification complete!")
print("=" * 50)

