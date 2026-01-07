from flask import Blueprint, render_template, request, jsonify, send_file
import psutil
import time
import datetime
import socket
import os
import threading
import platform
import sys
import json
import math
import subprocess
from capture_engine import engine

# Create a Blueprint (or just use app if we didn't want a blueprint, but separation is good)
# Since I'm creating routes.py, I'll make a function to register routes or use a Blueprint.
# Blueprint is cleaner.

api = Blueprint('api', __name__)

@api.route('/')
def home():
    return render_template('index.html')

@api.route('/api/stats')
def api_stats():
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        ram = psutil.virtual_memory().percent
        proc_count = len(psutil.pids())
        conn_count = 0
        try:
             conn_count = len(psutil.net_connections(kind='inet'))
        except: pass
        
        suspicious_count = 0
        try:
            for p in psutil.process_iter(['name', 'cpu_percent']):
                if p.info['cpu_percent'] > 80: suspicious_count += 1
        except: pass
        
        boot_time = psutil.boot_time()
        uptime = str(datetime.timedelta(seconds=int(time.time() - boot_time)))

        return jsonify({
            'cpu': cpu, 'ram': ram, 
            'process_count': proc_count,
            'connection_count': conn_count,
            'suspicious_count': suspicious_count,
            'uptime': uptime
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/processes')
def api_processes():
    procs = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'memory_percent', 'status', 'cpu_percent']):
            try:
                info = p.info.copy()
                info['num_threads'] = p.num_threads()
                try: info['connections'] = len(p.connections())
                except: info['connections'] = 0
                
                procs.append(info)
            except: pass
        procs.sort(key=lambda x: x.get('memory_percent', 0), reverse=True)
        return jsonify(procs[:150])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/process/<int:pid>')
def api_process_detail(pid):
    try:
        p = psutil.Process(pid)
        return jsonify({
            'name': p.name(),
            'status': p.status(),
            'ppid': p.ppid(),
            'create_time': datetime.datetime.fromtimestamp(p.create_time()).strftime('%Y-%m-%d %H:%M:%S'),
            'username': p.username(),
            'exe': p.exe(),
            'cmdline': ' '.join(p.cmdline()),
            'memory_info': {'rss': p.memory_info().rss, 'vms': p.memory_info().vms}
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/connections')
def api_connections():
    conns = []
    status_filter = request.args.get('status', '').upper()
    try:
        for c in psutil.net_connections(kind='inet'):
            try:
                if status_filter and c.status != status_filter:
                    continue
                conns.append({
                    'pid': c.pid,
                    'local': f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "N/A",
                    'remote': f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "N/A",
                    'status': c.status,
                    'type': 'TCP' if c.type == socket.SOCK_STREAM else 'UDP',
                    'process': psutil.Process(c.pid).name() if c.pid else "Unknown"
                })
            except: pass
        return jsonify(conns[:250])
    except Exception as e:
        return jsonify({'error': str(e)}), 500



# --- HELPER: Shannon Entropy for Random Name Detection ---
def calculate_entropy(text):
    if not text: return 0
    entropy = 0
    for x in range(256):
        p_x = float(text.count(chr(x))) / len(text)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

@api.route('/api/suspicious')
def api_suspicious():
    threats = []
    
    # 1. Gather Data for Baseline
    procs = []
    cpu_vals = []
    mem_vals = []
    thread_vals = []
    
    suspicious_names = ['nc', 'ncat', 'netcat', 'reverse', 'shell', 'backdoor', 'miner', 'keygen', 'mimikatz', 'hack', 'crack', 'payload']
    suspicious_paths = ['temp', 'tmp', 'appdata', 'downloads', 'users\\public']
    
    SYSTEM_PROCESS_PATHS = {
        'svchost.exe': 'c:\\windows\\system32',
        'csrss.exe': 'c:\\windows\\system32',
        'lsass.exe': 'c:\\windows\\system32',
        'services.exe': 'c:\\windows\\system32',
        'winlogon.exe': 'c:\\windows\\system32',
        'explorer.exe': 'c:\\windows'
    }

    try:
        # Get all connections first
        connections = {}
        try:
            for c in psutil.net_connections(kind='inet'):
                if c.pid:
                    key = int(c.pid)
                    if key not in connections: connections[key] = []
                    connections[key].append(c)
        except: pass

        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'num_threads', 'exe', 'ppid', 'cmdline']):
            try:
                # Force cache update for CPU
                p.cpu_percent() 
                procs.append(p)
            except: pass

        # Second pass for CPU (psutil needs delay for accurate reading, but we'll use what we have or 0)
        # In a real "AI" engine, we'd sample over time. Here we use instantaneous or initialized values.
        
        data_points = []
        for p in procs:
            try:
                info = p.info
                cpu = info['cpu_percent'] or 0
                mem = info['memory_percent'] or 0
                th = info['num_threads'] or 0
                
                cpu_vals.append(cpu)
                mem_vals.append(mem)
                thread_vals.append(th)
                
                data_points.append({
                    'p': p,
                    'info': info,
                    'cpu': cpu,
                    'mem': mem,
                    'th': th
                })
            except: pass

        # 2. Calculate Statistics (Mean & Std Dev)
        def get_stats(vals):
            if not vals: return 0, 1
            mean = sum(vals) / len(vals)
            variance = sum([((x - mean) ** 2) for x in vals]) / len(vals)
            std_dev = math.sqrt(variance)
            return mean, (std_dev if std_dev > 0 else 1)

        mu_cpu, sigma_cpu = get_stats(cpu_vals)
        mu_mem, sigma_mem = get_stats(mem_vals)
        mu_th, sigma_th = get_stats(thread_vals)

        # 3. Score Each Process
        for item in data_points:
            p = item['p']
            info = item['info']
            pid = info['pid']
            name = info['name'] or ""
            name_lower = name.lower()
            exe = info['exe'] or ""
            cmdline = " ".join(info['cmdline'] or [])
            
            score = 0
            reasons = []
            
            # --- FEATURE A: STATISTICAL ANOMALY (Z-Scores) ---
            z_cpu = (item['cpu'] - mu_cpu) / sigma_cpu
            z_mem = (item['mem'] - mu_mem) / sigma_mem
            z_th = (item['th'] - mu_th) / sigma_th
            
            if z_cpu > 3: 
                score += z_cpu * 10
                reasons.append(f"Abnormal CPU Usage (Z-Score: {round(z_cpu,1)})")
            
            if z_mem > 3:
                score += z_mem * 5
                reasons.append(f"Abnormal Memory Usage (Z-Score: {round(z_mem,1)})")

            # --- FEATURE B: ENTROPY ANALYSIS (Random Names) ---
            # Normal names (svchost.exe) have low entropy. Random (x78f9a.exe) have high.
            # Strip extension and dot
            name_core = name_lower.replace('.exe', '')
            entropy = calculate_entropy(name_core)
            if entropy > 3.8 and len(name_core) > 4: # Threshold
                score += 30
                reasons.append(f"High Entropy Name ({round(entropy,2)})")
            
            # --- FEATURE C: HEURISTICS (The "Expert Knowledge") ---
            
            # 1. Suspicious Keywords
            for s in suspicious_names:
                if s in name_lower:
                    score += 50
                    reasons.append(f"Suspicious Name Match: '{s}'")
                    break

            # 2. Network Anomalies
            has_conn = pid in connections
            is_shell = name_lower in ['cmd.exe', 'powershell.exe', 'bash.exe', 'wscript.exe']
            
            if has_conn:
                if is_shell:
                    score += 100
                    reasons.append("Shell with Network Connection (Reverse Shell?)")
                else:
                    # Connection from non-browser/non-system app
                    # This is weak without a whitelist, so we give small score
                    score += 5

            # 3. Path Anomalies
            if exe:
                if any(sp in exe.lower() for sp in suspicious_paths):
                    score += 40
                    reasons.append("Running from Temporary/Public Path")
                
                # Masquerading
                if name_lower in SYSTEM_PROCESS_PATHS:
                    expected = SYSTEM_PROCESS_PATHS[name_lower]
                    if expected not in exe.lower():
                        score += 100
                        reasons.append(f"System Process Impersonation (Expected {expected})")

            # --- FINAL VERDICT ---
            severity = 'low'
            if score > 20: severity = 'medium'
            if score > 50: severity = 'high'
            if score > 80: severity = 'critical'
            
            if score > 20: # Reporting Threshold
                threats.append({
                    'pid': pid,
                    'name': name,
                    'score': round(score),
                    'severity': severity,
                    'type': 'ANOMALY DETECTED' if not reasons[0].startswith('Suspicious') else 'SIGNATURE MATCH',
                    'message': " | ".join(reasons[:2]), # Top 2 reasons
                    'details': f"Anomaly Score: {round(score)} | Entropy: {round(entropy,2)}"
                })

        # Sort by Score DESC
        threats.sort(key=lambda x: x['score'], reverse=True)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500
        
    return jsonify({'threats': threats[:50]})

@api.route('/api/timeline')
def api_timeline():
    timeline = []
    try:
        for p in psutil.process_iter(['pid', 'name', 'create_time']):
            try:
                t = datetime.datetime.fromtimestamp(p.info['create_time'])
                timeline.append({
                    'time': t.strftime('%H:%M:%S'),
                    'event': f"Process Started: {p.info['name']}",
                    'details': f"PID: {p.info['pid']} | {t.strftime('%Y-%m-%d')}"
                })
            except: pass
        timeline.sort(key=lambda x: x['time'], reverse=True)
        return jsonify(timeline[:50])
    except:
        return jsonify([])

@api.route('/api/memory')
def api_memory():
    try:
        mem = psutil.virtual_memory()
        top = []
        for p in psutil.process_iter(['pid', 'name', 'memory_info']):
            try:
                mb = p.info['memory_info'].rss / 1024 / 1024
                if mb > 50:
                    top.append({'pid': p.info['pid'], 'name': p.info['name'], 'memory': round(mb, 2)})
            except: pass
        top.sort(key=lambda x: x['memory'], reverse=True)
        
        regions = [
            {'name': 'Heap', 'size': f'{round(mem.used/1024**3 * 0.4, 2)} GB', 'perms': 'RW-'},
            {'name': 'Stack', 'size': f'{round(mem.used/1024**3 * 0.1, 2)} GB', 'perms': 'RW-'},
            {'name': 'Code', 'size': f'{round(mem.used/1024**3 * 0.2, 2)} GB', 'perms': 'R-X'}
        ]
        return jsonify({
            'total': round(mem.total / 1024**3, 2),
            'available': round(mem.available / 1024**3, 2),
            'used': round(mem.used / 1024**3, 2),
            'percent': mem.percent,
            'top_processes': top[:20],
            'regions': regions
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/dump/<int:pid>')
def api_dump(pid):
    try:
        p = psutil.Process(pid)
        files = []
        try:
            for f in p.open_files(): files.append(f.path)
        except: pass
        
        libs = []
        try:
            for m in p.memory_maps(): libs.append(m.path)
        except: pass
        
        return jsonify({
            'pid': pid, 'name': p.name(),
            'memory_mb': round(p.memory_info().rss / 1024 / 1024, 2),
            'files': files[:20], 'libs': list(set(libs))[:20]
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/specs')
def api_specs():
    try:
        disks = []
        for part in psutil.disk_partitions():
            try:
                u = psutil.disk_usage(part.mountpoint)
                disks.append({'device': part.device, 'used': f"{round(u.used/1024**3,1)} GB", 'total': f"{round(u.total/1024**3,1)} GB", 'percent': u.percent})
            except: pass
            
        net = []
        for k, v in psutil.net_if_addrs().items():
            for a in v:
                if a.family == socket.AF_INET: net.append({'interface': k, 'address': a.address})

        return jsonify({
            'os': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'node': platform.node(),
            'processor': platform.processor(),
            'architecture': platform.machine(),
            'phys_cores': psutil.cpu_count(logical=False),
            'total_cores': psutil.cpu_count(logical=True),
            'disks': disks,
            'network': net
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/capture/info')
def api_capture_info():
    mem = psutil.virtual_memory()
    boot_time = psutil.boot_time()
    uptime = str(datetime.timedelta(seconds=int(time.time() - boot_time)))
    return jsonify({
        'hostname': platform.node(),
        'os': f"{platform.system()} {platform.release()}",
        'ram_total': f"{round(mem.total / 1024**3, 2)} GB",
        'uptime': uptime,
        'is_admin': engine.is_admin(),
        'is_exe': getattr(sys, 'frozen', False)
    })

@api.route('/api/capture/start', methods=['POST'])
def api_capture_start():
    if engine.status == 'running':
        return jsonify({'error': 'A capture is already in progress.'}), 409

    try:
        options = request.json
        case_id = options.get('case_id', 'CASE')
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Determine file extension
        requested_format = options.get('format', 'raw').lower()
        if requested_format not in ['raw', 'lime', 'mem']:
            requested_format = 'raw'
        
        filename = f"{case_id}_{timestamp}.{requested_format}"
        
        
        # --- FIX: Detect if running as EXE or Python Script ---
        # We use the centralized helper from CaptureEngine
        base_dir = engine.get_storage_dir()
        # -----------------------------------------------------

        output_path = os.path.join(base_dir, filename)

        # Run in thread so UI doesn't freeze
        thread = threading.Thread(target=engine.run_capture, args=(output_path, options, False))
        thread.start()
        
        return jsonify({'status': 'started', 'file': filename})
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/capture/status')
def api_capture_status():
    return jsonify({
        'status': engine.status,
        'progress': engine.progress,
        'message': engine.message,
        'filename': engine.filename
    })

@api.route('/api/download/<path:filename>')
def api_download(filename):
    try:
        base_dir = engine.get_storage_dir()
        return send_file(os.path.join(base_dir, filename), as_attachment=True)
    except Exception as e:
        return str(e), 404

@api.route('/api/reveal/<path:filename>')
def api_reveal(filename):
    try:
        base_dir = engine.get_storage_dir()
        full_path = os.path.join(base_dir, filename)
        
        if not os.path.exists(full_path):
            return jsonify({'error': 'File not found'}), 404
            
        # Open Explorer with file selected
        subprocess.Popen(f'explorer /select,"{full_path}"')
        return jsonify({'status': 'ok'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@api.route('/api/kill/<int:pid>', methods=['POST'])
def api_kill(pid):
    try:
        psutil.Process(pid).terminate()
        return jsonify({'message': f'Process {pid} terminated'})
    except Exception as e:
        return jsonify({'message': str(e)}), 500
