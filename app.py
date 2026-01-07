from flask import Flask
import argparse
import sys
import datetime
import os
import webbrowser
import threading

from routes import api
from capture_engine import engine

app = Flask(__name__)
app.register_blueprint(api)

BANNER = r"""
============================================================
   _   _  ______  __  __  _   _  ____  
  | \ | ||  ____| \ \/ / | | | |/ ___| 
  |  \| || |__     \  /  | | | |\___ \ 
  | |\  ||  __|    /  \  | |_| | ___) |
  |_| \_||______| /_/\_\  \___/ |____/ 
                                       
  NEXUS FORENSICS - MEMORY ACQUISITION TOOL v3.5
============================================================
"""

# --- MAIN ENTRY POINT ---
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Nexus Forensics: Magnet-Grade Memory Acquisition Tool")
    parser.add_argument('--cli', action='store_true', help="Run in Headless CLI Mode (Low Footprint)")
    parser.add_argument('--case', default="CASE001", help="Case ID for metadata")
    parser.add_argument('--format', default="raw", choices=['raw', 'lime', 'mem'], help="Output format")
    parser.add_argument('--output', help="Custom output filename (optional)")
    
    # Handle known args to avoid conflicts with Flask reloader
    args, unknown = parser.parse_known_args()

    print(BANNER)

    # --- MODE 1: HEADLESS CLI ---
    if args.cli:
        print("\n[!] RUNNING IN HEADLESS MODE (Best for Forensics)")
        print("[*] Minimizing memory footprint...")
        
        # Wizard Logic
        run_wizard = (args.case == "CASE001" and args.output is None)
        case_id = args.case
        fmt = args.format
        output = args.output
        
        if run_wizard:
            print("\n[?] INTERACTIVE CAPTURE WIZARD")
            print("    (Press ENTER to accept defaults)\n")
            try:
                i_case = input(f"    Case ID [{case_id}]: ").strip()
                if i_case: case_id = i_case
                i_fmt = input(f"    Output Format (raw/lime/mem) [{fmt}]: ").strip().lower()
                if i_fmt and i_fmt in ['raw', 'lime', 'mem']: fmt = i_fmt
                print(f"\n[+] Configuration: Case={case_id}, Format={fmt}")
                confirm = input("    Start Capture? [Y/n]: ").strip().lower()
                if confirm == 'n': sys.exit(0)
            except KeyboardInterrupt:
                sys.exit(0)

        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = output if output else f"{case_id}_{timestamp}.{fmt}"

        # Save Logic
        if getattr(sys, 'frozen', False):
            save_dir = os.path.dirname(sys.executable)
        else:
            save_dir = os.path.dirname(os.path.abspath(__file__))

        output_path = os.path.join(save_dir, filename)
        
        options = {
            "case_id": case_id,
            "investigator": os.getlogin(),
            "format": fmt,
            "timestamp": datetime.datetime.now().isoformat()
        }

        try:
            engine.run_capture(output_path, options, is_cli=True)
            sys.exit(0)
        except Exception as e:
            sys.exit(1)

    # --- GUI MODES (WEB or DESKTOP) ---
    else:
        # 1. Admin Check (Common for both)
        is_admin = engine.is_admin()
        if is_admin:
            print("[+] Admin Privileges: DETECTED (Ready for Capture)")
        else:
            print("[-] Admin Privileges: MISSING (Capture Disabled)")
            print("    Please Run as Administrator.")

        # 2. Check: Are we running as an EXE or a Python Script?
        is_frozen = getattr(sys, 'frozen', False)

        if is_frozen:
            # --- MODE 2: DESKTOP APP (EXE) ---
            # When running as .exe, we use pywebview to create a standalone window
            print("\n[!] RUNNING IN DESKTOP APP MODE")
            try:
                import webview
                # Create a native window hosting the Flask app
                webview.create_window("Nexus Forensics", app, width=1280, height=800)
                webview.start()
            except ImportError:
                print("[ERROR] 'pywebview' is missing. Falling back to browser mode.")
                # Fallback if library missing
                threading.Timer(1.5, lambda: webbrowser.open_new("http://127.0.0.1:5000/")).start()
                app.run(debug=False, host='0.0.0.0', port=5000, use_reloader=False)

        else:
            # --- MODE 3: WEB SERVER MODE (Python Script) ---
            # When running via 'python app.py', we behave like a website
            print("\n[!] RUNNING IN WEB SERVER MODE (Developer/Browser)")
            print("[*] Access at: http://127.0.0.1:5000")

            def open_dashboard():
                webbrowser.open_new("http://127.0.0.1:5000/")

            # Auto-open browser
            threading.Timer(1.5, open_dashboard).start()
            app.run(debug=True, host='0.0.0.0', port=5000, use_reloader=False)