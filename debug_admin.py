import ctypes
import os
import platform
import sys

def check_admin():
    print(f"Python Executable: {sys.executable}")
    print(f"Platform: {platform.system()} {platform.release()}")
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        print(f"IsUserAnAdmin() Result: {is_admin}")
        return is_admin
    except Exception as e:
        print(f"Error checking admin: {e}")
        return False

if __name__ == "__main__":
    print("-" * 40)
    print("ADMIN PRIVILEGE DEBUGGER")
    print("-" * 40)
    res = check_admin()
    if res:
        print("\n[SUCCESS] You have Administrator privileges.")
    else:
        print("\n[FAILURE] You do NOT have Administrator privileges.")
    input("\nPress Enter to exit...")
