# Nexus Forensics 🔍
**Magnet-Grade Memory Acquisition & Analysis Tool (v3.5)**

Nexus Forensics is a powerful, lightweight, and versatile tool designed for memory forensics and live system analysis. It provides immediate insight into system state, including running processes, network connections, and potential threats, while offering robust physical memory acquisition capabilities.

## Features

*   **Memory Acquisition**: Capture full physical RAM in multiple formats (`raw`, `lime`, `mem`) using industry-standard drivers (`winpmem` for Windows, `avml` for Linux).
*   **Live Dashboard**: Real-time monitoring of CPU, RAM, Process count, and Uptime.
*   **Threat Hunt Engine**:
    *   **Statistical Anomaly Detection**: Uses Z-Scores to identify processes with abnormal CPU/Memory/Thread usage.
    *   **Entropy Analysis**: Detects processes with random names (often malware) using Shannon Entropy.
    *   **Heuristics**: Flags suspicious names, paths (temp/public folders), and network behaviors (e.g., shells).
*   **Process Explorer**: View detailed process metadata, open files, loaded libraries (DLLs), and memory maps.
*   **Multi-Mode Operation**:
    *   **CLI Mode**: Minimal footprint, ideal for clean forensic collection.
    *   **Web Server Mode**: Full UI accessible via browser (useful for remote analysis).
    *   **Desktop App (EXE)**: Standalone native-like application for ease of use.

---

## 🛠️ Installation & Requirements

This project is built with **Python**. Ensure you have Python installed (Python 3.8+ recommended).

### Python Libraries
The following libraries are required:
*   `flask` (Web Framework)
*   `psutil` (System Monitoring & Process Management)
*   `pywebview` (GUI/Desktop App wrapper)
*   `requests`

### Setup
1.  **Clone the repository**:
    ```bash
    git clone https://github.com/risscheese/NexusForensics.git
    cd NexusForensics
    ```
2.  **Install Dependencies**:
    ```bash
    py -m pip install -r requirements.txt
    ```
    *(Note: If `requirements.txt` is missing, run: `py -m pip install flask psutil pywebview requests`)*

3.  **Binaries**:
    *   Ensure `winpmem_mini_x64_rc2.exe` is in the root folder for Windows memory capture.

---

## 📖 User Guidelines

Nexus Forensics can be run in **3 different environments** depending on your needs.

### 1. CLI Usage (Command Line Interface)
*Best for: Forensic data collection on live machines where minimizing noise/artifacts is critical.*

**How to run:**
Open your terminal (CMD or PowerShell) as **Administrator** and run:
```powershell
py app.py --cli
```

**Options:**
*   `--case [ID]`: Specify a Case ID (default: CASE001).
*   `--format [raw|lime|mem]`: Choose output format (default: raw).
*   `--output [filename]`: Specify exact output filename.

**Interactive Wizard:**
If you run `py app.py --cli` without arguments, it launches an interactive wizard:
```text
[?] INTERACTIVE CAPTURE WIZARD
    Case ID [CASE001]: <Enter Case ID>
    Output Format (raw/lime/mem) [raw]: <Enter Format>
    Start Capture? [Y/n]: y
```

### 2. Webpage Usage (Browser Mode)
*Best for: detailed analysis, development, or remote monitoring.*

**How to run:**
```powershell
py app.py
```
or
```
DOUBLE CLICK
run_admin.bat file in the fyp folder
```

*   The application will start a local web server at `http://127.0.0.1:5000`.
*   Your default browser should open automatically.
*   **Note**: To perform memory captures, you must run the terminal as **Administrator**.

**Features:**
*   **Dashboard**: Overview of system health.
*   **Processes**: Filterable list of all running processes.
*   **Threat Hunt**: detailed analysis of suspicious activities.
*   **Capture**: Click "Start Acquisition" to dump RAM through the UI.

### 3. EXE Usage (Standalone Desktop App)
*Best for: Portable usage on investigator machines or end-users.*

**How to run:**
1.  Locate `NexusForensics.exe` in the `dist` folder (see "Building" below).
2.  Right-click and **Run as Administrator** (Required for memory capture).
3.  A native window will appear displaying the interface.

**Building the EXE:**
If you want to compile the `.exe` yourself:
1.  Run the build script:
    ```powershell
    build_exe.bat
    ```
2.  Find the output in `dist/NexusForensics.exe`.

---

## ⚠️ Important Notes

*   **Administrator Privileges**: Memory acquisition (RAM dump) requires **Administrator (root)** privileges. If run without them, the tool will alert you, and capture features will be disabled.
*   **Antivirus Interference**: Security software may flag `winpmem` or process injection techniques used by `psutil`. You may need to whitelist the tool during analysis.
*   **Disk Space**: Memory dumps are large (equal to the size of physical RAM). Ensure sufficient disk space is available before starting a capture.

---

## 🎖 Credits & Acknowledgments
Nexus Forensics makes use of several open-source tools to function:

WinPMEM: The core driver used for physical memory acquisition on Windows. 
https://github.com/Velocidex/WinPmem

AVML: Used for memory acquisition on Linux systems.
https://github.com/microsoft/avml

Flask: Used for the web interface backend.
https://flask.palletsprojects.com/en/stable/

---
## ⚖️ License & Disclaimer
Disclaimer: This tool is intended for legal forensic analysis and educational purposes only. The developers of Nexus Forensics assume no liability and are not responsible for any misuse or damage caused by this program. Always ensure you have authorization before analyzing a system.

