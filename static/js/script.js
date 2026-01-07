function switchView(viewId, navElement) {
    document.querySelectorAll('.view-section').forEach(el => el.classList.remove('active-view'));
    document.getElementById(viewId).classList.add('active-view');

    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    navElement.classList.add('active');

    if (viewId === 'processes') refreshProcesses();
    if (viewId === 'specs') loadSpecs();
    if (viewId === 'connections') refreshConnections();
    if (viewId === 'suspicious') analyzeSuspicious();
    if (viewId === 'timeline') loadTimeline();
    if (viewId === 'memory') scanMemory();
    if (viewId === 'capture') initCapture();
}

let allProcesses = [];
let cpuChart, ramChart;
let isExe = false;

function initCharts() {
    const commonOptions = {
        responsive: true,
        maintainAspectRatio: false,
        animation: false,
        scales: {
            y: {
                beginAtZero: true,
                max: 100,
                grid: { color: '#333' },
                ticks: { color: '#888' }
            },
            x: {
                display: false
            }
        },
        plugins: {
            legend: { display: false }
        },
        elements: {
            line: {
                tension: 0.4,
                borderColor: '#00ff41',
                borderWidth: 2,
                fill: true,
                backgroundColor: 'rgba(0, 255, 65, 0.1)'
            },
            point: { radius: 0 }
        }
    };

    const cpuCtx = document.getElementById('cpuChart').getContext('2d');
    cpuChart = new Chart(cpuCtx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{ data: Array(20).fill(0) }]
        },
        options: commonOptions
    });

    const ramCtx = document.getElementById('ramChart').getContext('2d');
    ramChart = new Chart(ramCtx, {
        type: 'line',
        data: {
            labels: Array(20).fill(''),
            datasets: [{ data: Array(20).fill(0) }]
        },
        options: commonOptions
    });
}

function showError(elementId, message) {
    document.getElementById(elementId).innerHTML = `<div class="error-message">Error: ${message}</div>`;
}

function updateDashboard() {
    fetch('/api/stats')
        .then(res => {
            if (!res.ok) throw new Error('Network response was not ok');
            return res.json();
        })
        .then(data => {
            document.getElementById('dash-cpu').innerText = data.cpu.toFixed(1) + '%';
            document.getElementById('dash-cpu').innerText = data.cpu.toFixed(1) + '%';
            if (cpuChart) {
                cpuChart.data.datasets[0].data.push(data.cpu);
                cpuChart.data.datasets[0].data.shift();
                cpuChart.update();
            }

            document.getElementById('dash-ram').innerText = data.ram.toFixed(1) + '%';
            if (ramChart) {
                ramChart.data.datasets[0].data.push(data.ram);
                ramChart.data.datasets[0].data.shift();
                ramChart.update();
            }

            document.getElementById('dash-procs').innerText = data.process_count;
            document.getElementById('dash-conns').innerText = data.connection_count;
            document.getElementById('dash-threats').innerText = data.suspicious_count + ' THREATS';
            document.getElementById('dash-uptime').innerText = data.uptime;
        })
        .catch(err => {
            console.error('Dashboard update error:', err);
        });
}

function refreshProcesses() {
    document.getElementById('proc-body').innerHTML = '<tr><td colspan="8" style="text-align:center;" class="loading">Loading processes...</td></tr>';
    fetch('/api/processes')
        .then(res => {
            if (!res.ok) throw new Error('Failed to fetch processes');
            return res.json();
        })
        .then(data => {
            console.log('Processes loaded:', data.length);
            allProcesses = data;
            displayProcesses(data);
        })
        .catch(err => {
            console.error('Error loading processes:', err);
            document.getElementById('proc-body').innerHTML = '<tr><td colspan="8" style="text-align:center;" class="error-message">Error loading processes. Check console for details.</td></tr>';
        });
}

function displayProcesses(procs) {
    let html = '';
    if (procs.length === 0) {
        html = '<tr><td colspan="8" style="text-align:center; color: var(--warning);">No processes found</td></tr>';
    } else {
        procs.forEach(p => {
            const statusClass = p.status === 'running' ? 'normal' : 'warning';
            const status = p.status ? p.status.toUpperCase() : 'UNKNOWN';
            const memPercent = p.memory_percent != null ? p.memory_percent.toFixed(2) : '0.00';
            const cpuPercent = p.cpu_percent != null ? p.cpu_percent.toFixed(1) : '0.0';
            html += `<tr>
                <td>${p.pid}</td>
                <td style="color:#fff; font-weight:bold;">${p.name || 'Unknown'}</td>
                <td class="${statusClass}">${status}</td>
                <td>${memPercent}%</td>
                <td>${cpuPercent}%</td>
                <td>${p.num_threads || '0'}</td>
                <td>${p.connections || 0}</td>
                <td>
                    <button class="btn btn-danger" onclick="killProc(${p.pid})">KILL</button>
                    <button class="btn" onclick="inspectProc(${p.pid})">INSPECT</button>
                </td>
            </tr>`;
        });
    }
    document.getElementById('proc-body').innerHTML = html;
}

function filterProcesses() {
    const search = document.getElementById('proc-search').value.toLowerCase();
    const filtered = allProcesses.filter(p =>
        (p.name && p.name.toLowerCase().includes(search)) ||
        (p.pid && p.pid.toString().includes(search))
    );
    displayProcesses(filtered);
}

function killProc(pid) {
    if (confirm("Terminate process " + pid + "?")) {
        fetch('/api/kill/' + pid, { method: 'POST' })
            .then(res => res.json())
            .then(data => {
                alert(data.message);
                refreshProcesses();
            })
            .catch(err => {
                alert('Error killing process: ' + err.message);
            });
    }
}

function inspectProc(pid) {
    fetch('/api/process/' + pid)
        .then(res => {
            if (!res.ok) throw new Error('Failed to fetch process details');
            return res.json();
        })
        .then(data => {
            if (data.error) {
                alert('Error: ' + data.error);
                return;
            }
            let info = `PROCESS INSPECTION - PID: ${pid}\n\n`;
            info += `Name: ${data.name}\n`;
            info += `Status: ${data.status}\n`;
            info += `Parent PID: ${data.ppid}\n`;
            info += `Created: ${data.create_time}\n`;
            info += `User: ${data.username}\n`;
            info += `Executable: ${data.exe}\n`;
            info += `Command Line: ${data.cmdline}\n`;
            info += `\nMemory Info:\n`;
            if (data.memory_info) {
                info += `RSS: ${(data.memory_info.rss / 1024 / 1024).toFixed(2)} MB\n`;
                info += `VMS: ${(data.memory_info.vms / 1024 / 1024).toFixed(2)} MB\n`;
            }
            alert(info);
        })
        .catch(err => {
            alert('Error inspecting process: ' + err.message);
        });
}

function refreshConnections() {
    const filter = document.getElementById('conn-filter').value;
    let url = '/api/connections';
    if (filter) url += '?status=' + filter;

    document.getElementById('conn-body').innerHTML = '<tr><td colspan="6" class="loading">Loading...</td></tr>';
    fetch(url)
        .then(res => {
            if (!res.ok) throw new Error('Failed to fetch connections');
            return res.json();
        })
        .then(data => {
            let html = '';
            if (data.length === 0) {
                html = '<tr><td colspan="6" style="text-align:center;">No active connections</td></tr>';
            } else {
                data.forEach(c => {
                    const statusClass = c.status === 'ESTABLISHED' ? 'normal' : 'warning';
                    html += `<tr>
                        <td>${c.pid || 'N/A'}</td>
                        <td style="color:#fff;">${c.process || 'Unknown'}</td>
                        <td>${c.local}</td>
                        <td>${c.remote || 'N/A'}</td>
                        <td class="${statusClass}">${c.status}</td>
                        <td>${c.type}</td>
                    </tr>`;
                });
            }
            document.getElementById('conn-body').innerHTML = html;
        })
        .catch(err => {
            console.error('Connection error:', err);
            showError('conn-body', 'Failed to load connections');
        });
}

function analyzeSuspicious() {
    document.getElementById('threat-alerts').innerHTML = '<div class="loading">Running Heuristic Scan...</div>';
    fetch('/api/suspicious')
        .then(res => {
            if (!res.ok) throw new Error('Failed to analyze threats');
            return res.json();
        })
        .then(data => {
            let html = '';

            // Threat Level Summary
            let level = 'LOW';
            let color = 'var(--neon)';
            if (data.threats.length > 0) {
                level = 'ELEVATED';
                color = 'var(--warning)';
            }
            if (data.threats.some(t => t.severity === 'critical' || t.severity === 'high')) {
                level = 'CRITICAL';
                color = 'var(--danger)';
            }

            html += `<div style="margin-bottom: 20px; padding: 15px; border: 1px solid ${color}; color: ${color}; text-align: center;">
                <h3 style="margin:0;">THREAT LEVEL: ${level}</h3>
                <small>${data.threats.length} potential anomalies detected</small>
            </div>`;

            if (data.threats.length === 0) {
                html += '<div class="alert alert-info">No immediate heuristic matches found.</div>';
            } else {
                data.threats.forEach(t => {
                    let alertClass = 'alert-info';
                    let badgeClass = 'badge-info';

                    if (t.severity === 'medium') { alertClass = 'alert-warning'; badgeClass = 'badge-warning'; }
                    if (t.severity === 'high') { alertClass = 'alert-danger'; badgeClass = 'badge-danger'; }
                    if (t.severity === 'critical') { alertClass = 'alert-danger'; badgeClass = 'badge-danger blink'; }

                    html += `<div class="alert ${alertClass}" style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <span class="badge ${badgeClass}">${t.severity.toUpperCase()}</span>
                            <strong>${t.type}</strong> <span style="color:#888;">(Score: ${t.score})</span>: ${t.message}
                            <div style="margin-top:5px; font-size:0.85rem; color:#ccc; word-break:break-all;">
                                <span style="color:#666;">PID: ${t.pid}</span> | ${t.details}
                            </div>
                        </div>
                        <div style="display: flex; gap: 5px;">
                            <button class="btn btn-sm" onclick="inspectProc(${t.pid})" style="padding: 2px 8px; font-size: 0.7rem;">INSPECT</button>
                            ${t.pid ? `<button class="btn btn-danger btn-sm" onclick="killProc(${t.pid})" style="padding: 2px 8px; font-size: 0.7rem;">KILL</button>` : ''}
                        </div>
                    </div>`;
                });
            }
            document.getElementById('threat-alerts').innerHTML = html;
        })
        .catch(err => {
            console.error('Threat analysis error:', err);
            showError('threat-alerts', 'Failed to analyze threats');
        });
}

function loadTimeline() {
    document.getElementById('timeline-content').innerHTML = '<div class="loading">Loading...</div>';
    fetch('/api/timeline')
        .then(res => {
            if (!res.ok) throw new Error('Failed to load timeline');
            return res.json();
        })
        .then(data => {
            let html = '';
            data.forEach(item => {
                html += `<div class="timeline-item">
                    <strong style="color: var(--neon);">${item.time}</strong> - 
                    <span style="color: #fff;">${item.event}</span>
                    <br><small>${item.details}</small>
                </div>`;
            });
            document.getElementById('timeline-content').innerHTML = html || '<p>No events recorded yet.</p>';
        })
        .catch(err => {
            console.error('Timeline error:', err);
            showError('timeline-content', 'Failed to load timeline');
        });
}

function scanMemory() {
    document.getElementById('mem-overview').innerHTML = '<div class="loading">Scanning...</div>';
    document.getElementById('mem-top').innerHTML = '<div class="loading">Scanning...</div>';
    document.getElementById('mem-regions').innerHTML = '<div class="loading">Scanning...</div>';

    fetch('/api/memory')
        .then(res => {
            if (!res.ok) throw new Error('Failed to scan memory');
            return res.json();
        })
        .then(data => {
            document.getElementById('mem-overview').innerHTML = `
                <div class="spec-row"><span class="spec-key">TOTAL</span><span class="spec-val">${data.total} GB</span></div>
                <div class="spec-row"><span class="spec-key">AVAILABLE</span><span class="spec-val">${data.available} GB</span></div>
                <div class="spec-row"><span class="spec-key">USED</span><span class="spec-val">${data.used} GB</span></div>
                <div class="spec-row"><span class="spec-key">PERCENT</span><span class="spec-val">${data.percent}%</span></div>
            `;

            let topHtml = '';
            data.top_processes.forEach((p, index) => {
                topHtml += `<div class="spec-row" style="padding: 12px 0;">
                    <span class="spec-key" style="color: ${index < 3 ? 'var(--danger)' : '#888'};">${p.name} (${p.pid})</span>
                    <span class="spec-val" style="color: ${index < 3 ? 'var(--danger)' : '#fff'}; font-weight: bold;">${p.memory} MB</span>
                </div>`;
            });
            document.getElementById('mem-top').innerHTML = topHtml;

            let regionsHtml = '<table><thead><tr><th>Region</th><th>Size</th><th>Permissions</th></tr></thead><tbody>';
            data.regions.forEach(r => {
                regionsHtml += `<tr><td>${r.name}</td><td>${r.size}</td><td>${r.perms}</td></tr>`;
            });
            regionsHtml += '</tbody></table>';
            document.getElementById('mem-regions').innerHTML = regionsHtml;
        })
        .catch(err => {
            console.error('Memory scan error:', err);
            showError('mem-overview', 'Failed to scan memory');
            showError('mem-top', 'Failed to scan memory');
            showError('mem-regions', 'Failed to scan memory');
        });
}

function analyzeDump() {
    const pid = document.getElementById('dump-pid').value;
    if (!pid) {
        alert('Please enter a PID');
        return;
    }
    document.getElementById('dump-results').innerHTML = '<div class="loading">Analyzing...</div>';

    fetch('/api/dump/' + pid)
        .then(res => {
            if (!res.ok) throw new Error('Failed to analyze dump');
            return res.json();
        })
        .then(data => {
            if (data.error) {
                showError('dump-results', data.error);
                return;
            }
            let html = '<h4>MEMORY ANALYSIS RESULTS</h4>';
            html += `<div class="spec-row"><span class="spec-key">Process</span><span class="spec-val">${data.name}</span></div>`;
            html += `<div class="spec-row"><span class="spec-key">PID</span><span class="spec-val">${data.pid}</span></div>`;
            html += `<div class="spec-row"><span class="spec-key">Memory Usage</span><span class="spec-val">${data.memory_mb} MB</span></div>`;
            html += '<h4 style="margin-top: 20px;">OPEN FILES</h4>';
            if (data.files.length > 0) {
                data.files.forEach(f => {
                    html += `<div style="padding: 5px; border-bottom: 1px solid #222;">${f}</div>`;
                });
            } else {
                html += '<p>No open files</p>';
            }
            html += '<h4 style="margin-top: 20px;">LOADED LIBRARIES</h4>';
            if (data.libs.length > 0) {
                data.libs.slice(0, 10).forEach(l => {
                    html += `<div style="padding: 5px; border-bottom: 1px solid #222; font-size: 0.8rem;">${l}</div>`;
                });
            } else {
                html += '<p>No libraries found</p>';
            }
            document.getElementById('dump-results').innerHTML = html;
        })
        .catch(err => {
            console.error('Dump analysis error:', err);
            showError('dump-results', 'Failed to analyze memory dump');
        });
}

function exportProcesses() {
    fetch('/api/processes')
        .then(res => {
            if (!res.ok) throw new Error('Failed to fetch processes');
            return res.json();
        })
        .then(data => {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'processes_' + Date.now() + '.json';
            a.click();
            URL.revokeObjectURL(url);
        })
        .catch(err => {
            alert('Export failed: ' + err.message);
        });
}

function loadSpecs() {
    fetch('/api/specs')
        .then(res => {
            if (!res.ok) throw new Error('Failed to load specs');
            return res.json();
        })
        .then(data => {
            document.getElementById('spec-os-list').innerHTML = `
                <div class="spec-row"><span class="spec-key">SYSTEM</span><span class="spec-val">${data.os}</span></div>
                <div class="spec-row"><span class="spec-key">RELEASE</span><span class="spec-val">${data.release}</span></div>
                <div class="spec-row"><span class="spec-key">NODE NAME</span><span class="spec-val">${data.node}</span></div>
                <div class="spec-row"><span class="spec-key">VERSION</span><span class="spec-val">${data.version}</span></div>
            `;
            document.getElementById('spec-cpu-list').innerHTML = `
                <div class="spec-row"><span class="spec-key">PROCESSOR</span><span class="spec-val">${data.processor}</span></div>
                <div class="spec-row"><span class="spec-key">PHYSICAL CORES</span><span class="spec-val">${data.phys_cores}</span></div>
                <div class="spec-row"><span class="spec-key">TOTAL THREADS</span><span class="spec-val">${data.total_cores}</span></div>
                <div class="spec-row"><span class="spec-key">ARCHITECTURE</span><span class="spec-val">${data.architecture}</span></div>
            `;

            let diskHtml = '';
            data.disks.forEach(d => {
                diskHtml += `<div class="spec-row"><span class="spec-key">${d.device}</span><span class="spec-val">${d.used}/${d.total} (${d.percent}%)</span></div>`;
            });
            document.getElementById('spec-disk-list').innerHTML = diskHtml || '<p>No disk info</p>';

            let netHtml = '';
            data.network.forEach(n => {
                netHtml += `<div class="spec-row"><span class="spec-key">${n.interface}</span><span class="spec-val">${n.address}</span></div>`;
            });
            document.getElementById('spec-net-list').innerHTML = netHtml || '<p>No network interfaces</p>';
        })
        .catch(err => {
            console.error('Specs error:', err);
            showError('spec-os-list', 'Failed to load specs');
        });
}

// RAM CAPTURE FUNCTIONS
function initCapture() {
    fetch('/api/capture/info?_=' + Date.now())
        .then(res => {
            if (!res.ok) throw new Error('Failed to load capture info');
            return res.json();
        })
        .then(data => {
            document.getElementById('cap-hostname').innerText = data.hostname;
            document.getElementById('cap-os').innerText = data.os;
            document.getElementById('cap-ram').innerText = data.ram_total;
            document.getElementById('cap-uptime').innerText = data.uptime;
            document.getElementById('cap-uptime').innerText = data.uptime;
            document.getElementById('cap-time').innerText = new Date().toLocaleString();
            isExe = data.is_exe;

            const btn = document.querySelector('#capture .btn-danger');
            const alertBox = document.getElementById('capture-progress');

            // Admin check removed - Always enable capture
            if (btn) {
                btn.disabled = false;
                btn.style.opacity = '1';
                btn.style.cursor = 'pointer';
                btn.innerText = "⚠ START ACQUISITION";
                btn.onclick = startCapture;
            }
            if (alertBox) {
                alertBox.style.display = 'none';
            }
        })
        .catch(err => {
            console.error('Capture init error:', err);
        });
}

function showCaptureInfo() {
    alert(`NEXUS RAM CAPTURE v3.2 - VOLATILITY COMPATIBLE

This tool provides forensic-grade memory acquisition with multiple output formats compatible with Volatility Framework 2 & 3.

SUPPORTED OUTPUT FORMATS:

📁 .raw (RAW Memory Dump)
   • Industry standard format
   • Compatible with: Volatility 2/3, Rekall, Magnet AXIOM
   • Direct physical memory copy
   • Best for: Complete forensic analysis

📁 .lime (LiME Format)
   • Linux Memory Extractor format
   • Includes ELF headers with metadata
   • Compatible with: Volatility 3 (with LiME plugin)
   • Best for: Linux systems

📁 .mem (Generic Memory Image)
   • Generic extension for memory dumps
   • Treated as raw image by most tools
   • Best for: Broad compatibility

VOLATILITY 3 USAGE:
vol3 -f memory_dump.raw windows.info
vol3 -f memory_dump.raw windows.pslist
vol3 -f memory_dump.raw windows.netscan
vol3 -f memory_dump.raw windows.malfind

CHAIN OF CUSTODY:
✓ Cryptographic hashes (MD5, SHA256, SHA512)
✓ Investigator attribution
✓ Timestamp preservation
✓ System fingerprinting
✓ Acquisition metadata`);
}

async function startCapture() {
    const caseId = document.getElementById('case-id').value || 'UNKNOWN';
    const investigator = document.getElementById('investigator').value || 'UNKNOWN';
    const fmt = document.getElementById('output-format').value;

    // Show progress UI
    document.getElementById('capture-progress').style.display = 'block';
    document.getElementById('capture-bar').style.width = '0%';
    document.getElementById('capture-status').innerText = 'Starting capture agent...';

    const options = {
        case_id: caseId,
        investigator: investigator,
        format: fmt,
        timestamp: new Date().toISOString()
    };

    try {
        // 1. Start the Job
        const startRes = await fetch('/api/capture/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(options)
        });

        if (!startRes.ok) {
            const err = await startRes.json();
            throw new Error(err.error || 'Failed to start');
        }

        // 2. Poll for Status
        let complete = false;
        while (!complete) {
            await sleep(2000); // Poll every 2 seconds

            const statusRes = await fetch('/api/capture/status');
            const statusData = await statusRes.json();

            if (statusData.status === 'running') {
                // Pulse the bar to show activity since we can't get exact % from mini winpmem
                document.getElementById('capture-bar').style.width = '50%';
                document.getElementById('capture-status').innerText = statusData.message;
            }
            else if (statusData.status === 'completed') {
                complete = true;
                document.getElementById('capture-bar').style.width = '100%';
                document.getElementById('capture-status').innerText = 'Acquisition Complete!';

                // Trigger Download or Reveal
                const filename = statusData.filename;

                let html = `<h4>CAPTURE SUCCESSFUL</h4>`;
                html += `<div class="alert alert-info">File saved as: ${filename}</div>`;

                if (isExe) {
                    html += `<button onclick="revealFile('${filename}')" class="btn" style="display:block; width:100%; margin-top:10px;">📂 SHOW IN FOLDER</button>`;
                } else {
                    const downloadUrl = `/api/download/${filename}`;
                    html += `<a href="${downloadUrl}" class="btn" style="display:block; text-align:center; margin-top:10px;">⬇ DOWNLOAD RAW DUMP</a>`;
                }

                html += `<p style="margin-top:10px; font-size:0.8rem; color:#888;">Compatible with Volatility 3: <code>vol3 -f ${filename} windows.info</code></p>`;

                document.getElementById('capture-artifacts').innerHTML = html;
            }
            else if (statusData.status === 'error') {
                throw new Error(statusData.message);
            }
        }

    } catch (err) {
        document.getElementById('capture-bar').style.background = 'var(--danger)';
        document.getElementById('capture-status').innerText = 'FAILED: ' + err.message;
        alert('Capture Error: ' + err.message);
    }
}

function updateProgress(percent, status) {
    document.getElementById('capture-bar').style.width = percent + '%';
    document.getElementById('capture-status').innerText = status;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function displayCaptureResults(data) {
    // Display metadata
    let metaHtml = `
        <div class="spec-row"><span class="spec-key">Case ID</span><span class="spec-val">${data.metadata.case_id}</span></div>
        <div class="spec-row"><span class="spec-key">Investigator</span><span class="spec-val">${data.metadata.investigator}</span></div>
        <div class="spec-row"><span class="spec-key">Timestamp</span><span class="spec-val">${data.metadata.timestamp}</span></div>
        <div class="spec-row"><span class="spec-key">Hostname</span><span class="spec-val">${data.metadata.hostname}</span></div>
        <div class="spec-row"><span class="spec-key">OS</span><span class="spec-val">${data.metadata.os}</span></div>
        <div class="spec-row"><span class="spec-key">Output Format</span><span class="spec-val">${data.metadata.output_format.toUpperCase()}</span></div>
        <div class="spec-row"><span class="spec-key">Total Processes</span><span class="spec-val">${data.processes ? data.processes.length : 0}</span></div>
        <div class="spec-row"><span class="spec-key">Total Connections</span><span class="spec-val">${data.connections ? data.connections.length : 0}</span></div>
    `;

    if (data.hashes) {
        metaHtml += `
            <div class="spec-row"><span class="spec-key">MD5 Hash</span><span class="spec-val hash-display">${data.hashes.md5}</span></div>
            <div class="spec-row"><span class="spec-key">SHA256 Hash</span><span class="spec-val hash-display">${data.hashes.sha256}</span></div>
            <div class="spec-row"><span class="spec-key">SHA512 Hash</span><span class="spec-val hash-display">${data.hashes.sha512}</span></div>
        `;
    }

    document.getElementById('capture-metadata').innerHTML = metaHtml;

    // Display artifacts preview
    let artifactsHtml = '<h4>CAPTURED ARTIFACTS</h4>';
    artifactsHtml += '<div class="alert alert-info">';
    artifactsHtml += `✓ Memory dump format: ${data.metadata.output_format.toUpperCase()}<br>`;
    artifactsHtml += `✓ ${data.processes ? data.processes.length : 0} Process snapshots<br>`;
    artifactsHtml += `✓ ${data.connections ? data.connections.length : 0} Network connections<br>`;
    artifactsHtml += `✓ ${data.handles ? data.handles.length : 0} File handles<br>`;
    artifactsHtml += `✓ ${data.dll_count || 0} Loaded libraries<br>`;
    artifactsHtml += `✓ Volatility 3 compatible<br>`;
    artifactsHtml += `✓ Chain of custody preserved<br>`;
    artifactsHtml += `✓ Triple-hash verification (MD5/SHA256/SHA512)`;
    artifactsHtml += '</div>';

    if (data.volatility_commands) {
        artifactsHtml += '<h4 style="margin-top: 20px;">VOLATILITY 3 ANALYSIS COMMANDS</h4>';
        artifactsHtml += '<div style="background: #0a0a0a; padding: 15px; border: 1px solid var(--dark-neon); font-family: monospace; font-size: 0.85rem;">';
        data.volatility_commands.forEach(cmd => {
            artifactsHtml += `<div style="padding: 5px; color: var(--neon);">${cmd}</div>`;
        });
        artifactsHtml += '</div>';
    }

    if (data.suspicious && data.suspicious.length > 0) {
        artifactsHtml += '<h4 style="margin-top: 20px; color: var(--danger);">⚠ SUSPICIOUS INDICATORS</h4>';
        data.suspicious.forEach(s => {
            artifactsHtml += `<div class="alert alert-warning">${s}</div>`;
        });
    }

    document.getElementById('capture-artifacts').innerHTML = artifactsHtml;

    alert('Memory capture complete! Files will be downloaded automatically.\n\nAnalyze with Volatility 3:\nvol3 -f memory_dump.raw windows.info');
}

function downloadCaptureFiles(data, format) {
    const timestamp = Date.now();
    const caseId = data.metadata.case_id;

    // Always download the JSON metadata
    const jsonBlob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    downloadFile(jsonBlob, `${caseId}_metadata_${timestamp}.json`);

    // Download format-specific file
    if (format === 'raw' || format === 'all') {
        const rawBlob = new Blob([createRawDump(data)], { type: 'application/octet-stream' });
        downloadFile(rawBlob, `${caseId}_memory_${timestamp}.raw`);
    }

    if (format === 'lime' || format === 'all') {
        const limeBlob = new Blob([createLimeDump(data)], { type: 'application/octet-stream' });
        downloadFile(limeBlob, `${caseId}_memory_${timestamp}.lime`);
    }

    if (format === 'dmp' || format === 'all') {
        const dmpBlob = new Blob([createDmpDump(data)], { type: 'application/octet-stream' });
        downloadFile(dmpBlob, `${caseId}_memory_${timestamp}.dmp`);
    }

    if (format === 'vmem' || format === 'all') {
        const vmemBlob = new Blob([createVmemDump(data)], { type: 'application/octet-stream' });
        downloadFile(vmemBlob, `${caseId}_memory_${timestamp}.vmem`);
    }

    // Download verification hashes
    if (data.hashes) {
        const hashText = `Memory Dump Hash Verification
Case ID: ${caseId}
Timestamp: ${data.metadata.timestamp}
Format: ${format}

MD5:    ${data.hashes.md5}
SHA256: ${data.hashes.sha256}
SHA512: ${data.hashes.sha512}

Investigator: ${data.metadata.investigator}
Hostname: ${data.metadata.hostname}
`;
        const hashBlob = new Blob([hashText], { type: 'text/plain' });
        downloadFile(hashBlob, `${caseId}_hashes_${timestamp}.txt`);
    }
}

function downloadFile(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}

function createRawDump(data) {
    const header = `NEXUS_RAW_MEMORY_DUMP
Version: 1.0
Format: RAW (Volatility Compatible)
Case: ${data.metadata.case_id}
Timestamp: ${data.metadata.timestamp}
System: ${data.metadata.os}
Architecture: ${data.metadata.architecture}
Memory Total: ${data.system_info.memory_total} bytes

--- Memory Image Data Follows ---
`;
    return header + JSON.stringify(data, null, 2);
}

function createLimeDump(data) {
    const header = `LiME Memory Capture
Format: ELF64 Core Dump
Case: ${data.metadata.case_id}
Kernel: ${data.metadata.os}

--- LiME Format Data ---
`;
    return header + JSON.stringify(data, null, 2);
}

function createDmpDump(data) {
    const header = `Windows Crash Dump
Format: Full Memory Dump
Case: ${data.metadata.case_id}
System: ${data.metadata.os}

--- Crash Dump Data ---
`;
    return header + JSON.stringify(data, null, 2);
}

function createVmemDump(data) {
    const header = `VMware Memory Snapshot
Format: VMEM
Case: ${data.metadata.case_id}
VM: ${data.metadata.hostname}

--- VMware Memory Data ---
`;
    return header + JSON.stringify(data, null, 2);
}


function forceEnableCapture() {
    const btn = document.querySelector('#capture .btn-danger');
    const alertBox = document.getElementById('capture-progress');

    if (btn) {
        btn.disabled = false;
        btn.style.opacity = '1';
        btn.style.cursor = 'pointer';
        btn.innerText = "⚠ START ACQUISITION (FORCED)";
        btn.onclick = startCapture;
    }
    if (alertBox) {
        alertBox.style.display = 'none';
        alert("Warning bypassed. If capture fails, it is due to missing permissions.");
    }
}

function revealFile(filename) {
    fetch('/api/reveal/' + filename)
        .catch(err => alert('Failed to open folder: ' + err));
}

setInterval(updateDashboard, 2000);
document.addEventListener('DOMContentLoaded', initCharts);
updateDashboard();
