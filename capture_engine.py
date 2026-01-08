import psutil
import platform
import socket
import datetime
import time
import hashlib
import os
import json
import subprocess
import threading
import shutil
import sys
import ctypes

# --- CORE LOGIC (UNIFIED FOR CLI AND WEB) ---
class CaptureEngine:
    def __init__(self):
        self.status = 'idle'
        self.progress = 0
        self.message = 'Ready'
        self.filename = None
        self.error = None

    def is_admin(self):
        """Checks for administrative privileges with fallback."""
        if platform.system() == 'Windows':
            try:
                if ctypes.windll.shell32.IsUserAnAdmin() != 0:
                    return True
            except: pass
            return False
        else:
            try:
                return os.geteuid() == 0
            except:
                return False

    def check_requirements(self):
        """Checks if external tools exist and disk space is sufficient."""
        # 1. Tool Check
        current_os = platform.system()
        base_dir = os.path.dirname(os.path.abspath(__file__))
        
        tool_path = None
        if current_os == 'Windows':
            tool_path = os.path.join(base_dir, 'winpmem.exe')
        elif current_os == 'Linux':
            tool_path = os.path.join(base_dir, 'avml')
        
        # NOTE: For safety, if tool is missing we log warning but allow app to run (Analysis still works)
        if tool_path and not os.path.exists(tool_path):
            print(f"Warning: Capture tool not found at {tool_path}. RAM Capture will fail, but Analysis will work.")
        
        return tool_path

    def get_storage_dir(self):
        """Returns the directory where persistent files (captures) should be stored."""
        if getattr(sys, 'frozen', False):
            # If EXE: Save in the folder where the .exe is located
            return os.path.dirname(sys.executable)
        else:
            # If Script: Save in the current code folder
            return os.path.dirname(os.path.abspath(__file__))

    def _cli_spinner(self):
        spinner = ['|', '/', '-', '\\']
        idx = 0
        while self.status == 'running':
            sys.stdout.write(f"\r[*] Capturing... {spinner[idx]} ")
            sys.stdout.flush()
            idx = (idx + 1) % len(spinner)
            time.sleep(0.1)
        sys.stdout.write("\r[*] Capturing... Done!   \n")

    def run_capture(self, output_path, options, is_cli=False):
        """Executes the capture process."""
        self.status = 'running'
        self.message = 'Initializing...'
        
        try:
            tool_path = self.check_requirements()
            if not tool_path or not os.path.exists(tool_path):
                 raise FileNotFoundError("Capture tool (winpmem/avml) not found. Please place it in the app folder.")

            current_os = platform.system()
            
            # Disk Check
            mem = psutil.virtual_memory()
            required_bytes = mem.total + (500 * 1024 * 1024)
            free_bytes = shutil.disk_usage(os.path.dirname(output_path)).free
            
            if free_bytes < required_bytes:
                raise IOError(f"Insufficient disk space. Need {round(required_bytes/1024**3, 2)} GB.")

            # Prepare Command
            cmd = []
            if current_os == 'Windows':
                self.message = 'Acquiring Windows physical memory (WinPMEM)...'
                cmd = [tool_path, output_path]
            elif current_os == 'Linux':
                self.message = 'Acquiring Linux memory (LiME/AVML)...'
                os.chmod(tool_path, 0o755)
                cmd = ['sudo', tool_path, output_path]
            
            if is_cli:
                print(f"[+] Starting capture: {' '.join(cmd)}")
                spinner_thread = threading.Thread(target=self._cli_spinner)
                spinner_thread.start()

            # DEBUG: Verify Admin Status before Popen
            try:
                is_admin_check = ctypes.windll.shell32.IsUserAnAdmin()
                print(f"[DEBUG] run_capture Admin Check: {is_admin_check}")
            except:
                print("[DEBUG] Admin check failed")

            # Execute
            startupinfo = None
            if os.name == 'nt':
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW

            process = subprocess.Popen(
                cmd, 
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE, 
                text=True,
                startupinfo=startupinfo
            )
            
            stdout, stderr = process.communicate()
            
            # --- IMPROVED ERROR HANDLING ---
            # WinPMEM returns 1 if it hits "bad pages" (marked 'x' in logs) even if 99% succeeded.
            # We check if the file exists and is substantial (> 100MB) to declare success.
            file_exists = os.path.exists(output_path)
            file_size = os.path.getsize(output_path) if file_exists else 0
            
            if process.returncode != 0:
                 if file_exists and file_size > (100 * 1024 * 1024):
                     # Treat as warning/success
                     print(f"[WARNING] Tool reported read errors (Code {process.returncode}), but dump file was created.")
                 else:
                     raise Exception(f"Tool failed (Code {process.returncode}): {stderr or stdout}")

            # Verification
            if file_exists and file_size > 0:
                self.status = 'completed'
                self.progress = 100
                self.message = f'Acquisition successful ({current_os}).'
                self.filename = os.path.basename(output_path)
                
                # Save Metadata Sidecar
                meta_path = output_path + ".json"
                options['captured_os'] = current_os
                options['file_size_bytes'] = file_size
                with open(meta_path, 'w') as f:
                    json.dump(options, f, indent=2)
                
                if is_cli:
                    print(f"[SUCCESS] Memory dumped to: {output_path}")
            else:
                raise Exception("Output file is missing or empty after capture.")

        except Exception as e:
            self.status = 'error'
            self.message = str(e)
            self.error = str(e)
            if is_cli:
                print(f"[ERROR] {str(e)}")
            raise e

# Global Engine Instance
engine = CaptureEngine()

