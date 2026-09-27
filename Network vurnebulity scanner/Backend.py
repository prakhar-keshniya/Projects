from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
import nmap
import re
import os
import sys

# Flask uses ./templates/ and ./static/ by default
app = Flask(__name__)
CORS(app)

@app.route('/')
def home():
    return render_template('index.html')

import shutil

# NMAP PATH — OS specific logic for Render Web Service deployment
if sys.platform == 'win32':
    # 1. Check system PATH
    nmap_in_path = shutil.which("nmap.exe") or shutil.which("nmap")
    
    # 2. Check known custom and standard paths
    possible_paths = [
        r"D:\L_Mahesh\Prakhar\Cybersecurity\Programming\Python\Complete python\Cyber python\Cyber tool\Nmap\nmap.exe",
        r"D:\L_Mahesh\Prakhar\Programming\Python\Cyber python\Cyber tool\Nmap\nmap.exe",
        r"C:\Program Files (x86)\Nmap\nmap.exe",
        r"C:\Program Files\Nmap\nmap.exe"
    ]
    
    NMAP_PATH = None
    if nmap_in_path:
        NMAP_PATH = nmap_in_path
    else:
        for path in possible_paths:
            if os.path.exists(path):
                NMAP_PATH = path
                break
                
    if not NMAP_PATH:
        raise Exception("Nmap not found! Please download/install Nmap or update the search path.")
        
    print(f"Using Nmap path: {NMAP_PATH}")
    scanner = nmap.PortScanner(nmap_search_path=(NMAP_PATH,))
else:
    # On Linux environments like Render, nmap is globally installed via apt
    scanner = nmap.PortScanner()


# INPUT VALIDATION
RE_IPV4   = r'^(\d{1,3}\.){3}\d{1,3}$'
RE_DOMAIN = r'^[a-zA-Z0-9.-]+$'

def is_valid_target(target):
    if not target or len(target) > 253:
        return False
    if re.match(RE_IPV4, target):
        return all(0 <= int(o) <= 255 for o in target.split('.'))
    if re.match(RE_DOMAIN, target):
        return True
    return False


# PORT DATABASE  Format: port -> (service_name, risk, recommendation)
PORT_DB = {
    # Critical
    21:    ("FTP",        "critical", "Disable FTP or use SFTP"),
    23:    ("Telnet",     "critical", "Disable Telnet"),
    445:   ("SMB",        "critical", "Block SMB from internet"),
    3389:  ("RDP",        "critical", "Restrict RDP"),
    5900:  ("VNC",        "critical", "Secure or disable VNC"),
    6379:  ("Redis",      "critical", "Bind to localhost & auth"),
    27017: ("MongoDB",    "critical", "Enable auth & restrict access"),

    # High
    22:    ("SSH",        "high",     "Use key-based auth"),
    25:    ("SMTP",       "high",     "Secure mail server"),
    53:    ("DNS",        "high",     "Restrict recursion"),
    110:   ("POP3",       "high",     "Use POP3S"),
    139:   ("NetBIOS",    "high",     "Disable if unused"),
    143:   ("IMAP",       "high",     "Use IMAPS"),
    389:   ("LDAP",       "high",     "Secure with LDAPS"),
    636:   ("LDAPS",      "high",     "Check cert & config"),
    2049:  ("NFS",        "high",     "Restrict access"),
    2082:  ("cPanel",     "high",     "Use HTTPS & strong auth"),
    2083:  ("cPanel-SSL", "high",     "Harden access"),
    2181:  ("Zookeeper",  "high",     "Restrict access"),
    5601:  ("Kibana",     "high",     "Add authentication"),

    # Medium
    80:    ("HTTP",       "medium",   "Use HTTPS"),
    443:   ("HTTPS",      "medium",   "Check TLS config"),
    8080:  ("HTTP-Alt",   "medium",   "Secure alt port"),
    8443:  ("HTTPS-Alt",  "medium",   "Check SSL config"),
    3000:  ("Dev Server", "medium",   "Restrict public access"),
    5000:  ("Flask",      "medium",   "Do not expose in prod"),
    7001:  ("WebLogic",   "medium",   "Patch vulnerabilities"),
    7002:  ("WebLogic-SSL","medium",  "Secure config"),
    8000:  ("HTTP-Dev",   "medium",   "Restrict access"),
    8888:  ("Jupyter",    "medium",   "Use token/password"),
    9200:  ("Elasticsearch","medium", "Enable auth"),
    15672: ("RabbitMQ",   "medium",   "Secure dashboard"),

    # Low
    20:    ("FTP-Data",   "low",      "Used with FTP"),
    123:   ("NTP",        "low",      "Check misuse"),
    161:   ("SNMP",       "low",      "Disable public access"),
    179:   ("BGP",        "low",      "Restrict peers"),
    515:   ("LPD",        "low",      "Disable if unused"),
    1900:  ("UPnP",       "low",      "Disable on public net"),
}

# RISK CALCULATION
def calculate_risk(ports):
    score = 0
    for p in ports:
        if p["state"] != "open":
            continue
        if p["risk"] == "critical":   score += 20
        elif p["risk"] == "high":     score += 12
        elif p["risk"] == "medium":   score += 6
        else:                         score += 2
    score = min(score, 100)
    if score >= 70:   label = "HIGH RISK"
    elif score >= 40: label = "MEDIUM RISK"
    elif score > 0:   label = "LOW RISK"
    else:             label = "MINIMAL RISK"
    return score, label

# OS INFO EXTRACTOR  ← NEW
def extract_os_info(scanner, host):
    """
    Returns dict with OS details or None if not detected.
    nmap stores OS info in scanner[host]['osmatch']
    Each match looks like:
    {
    'name': 'Linux 3.1',
    'accuracy': '98',
    'osclass': [{ 'type': 'general purpose', 'vendor': 'Linux',
                    'osfamily': 'Linux', 'osgen': '3.X', ... }]
    }
    """
    try:
        osmatch = scanner[host].get('osmatch', [])
        if not osmatch:
            return None

        best = osmatch[0]
        result = {
            "name":     best.get('name', 'Unknown'),
            "accuracy": best.get('accuracy', '—'),
        }

        osclass = best.get('osclass', [])
        if osclass:
            cls = osclass[0]
            result["type"]       = cls.get('type', '')
            result["vendor"]     = cls.get('vendor', '')
            result["family"]     = cls.get('osfamily', '')
            result["generation"] = cls.get('osgen', '')

        result = {k: v for k, v in result.items() if v and v != '—' or k in ('name', 'accuracy')}
        return result

    except Exception:
        return None


# SCAN PROFILES
SCAN_ARGS = {
    "fast":       "-F",
    "default":    "-sV",
    "service":    "-sV -sC",
    "os":         "-O",       
    "aggressive": "-A",
}

# SCAN ROUTE
@app.route('/scan', methods=['POST'])
def scan():
    data    = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Request must be JSON"}), 400

    target  = (data.get('target')  or '').strip()
    profile = (data.get('profile') or 'fast').strip()

    if not is_valid_target(target):
        return jsonify({"error": "Invalid target"}), 400

    args = SCAN_ARGS.get(profile, "-F")

    try:
        scanner.scan(hosts=target, arguments=args)
    except nmap.PortScannerError as e:
        err_msg = str(e)
        if profile == 'os' and ('root' in err_msg.lower() or 'permission' in err_msg.lower() or 'privileged' in err_msg.lower()):
            return jsonify({"error": "OS Detection requires Administrator privileges. Right-click your terminal and choose 'Run as Administrator', then try again."}), 500
        return jsonify({"error": f"Nmap error: {err_msg}"}), 500
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    if not scanner.all_hosts():
        return jsonify({"error": "Target unreachable or no hosts found"}), 404

    ports_data      = []
    vulnerabilities = []
    seen_vulns      = set()
    os_info         = None   

    for host in scanner.all_hosts():

        if profile in ('os', 'aggressive') and os_info is None:
            os_info = extract_os_info(scanner, host)

        for proto in scanner[host].all_protocols():
            for port in sorted(scanner[host][proto].keys()):

                port_info = scanner[host][proto][port]
                state     = port_info.get('state',   'closed')
                service   = port_info.get('name',    'unknown')
                product   = port_info.get('product', '')
                version   = port_info.get('version', '')
                svc_full  = f"{product} {version}".strip() if product else service

                if port in PORT_DB:
                    service_name, risk, recommendation = PORT_DB[port]
                    display_service = svc_full if (svc_full and svc_full != 'unknown') else service_name
                else:
                    display_service = svc_full or service
                    risk            = "low"
                    recommendation  = "Review this service"

                ports_data.append({
                    "port":           f"{port}/{proto}",
                    "service":        display_service,
                    "serviceInfo":    service,
                    "state":          state,
                    "risk":           risk,
                    "recommendation": recommendation,
                })

                # Vulnerability cards
                if state == "open" and port not in seen_vulns:
                    if port == 21:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "FTP Exposed",        "risk": "critical", "cve": "CVE-1999-0497", "desc": "FTP transmits credentials in plaintext."})
                    elif port == 23:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Telnet Detected",    "risk": "critical", "cve": "CVE-1999-0619", "desc": "Telnet is completely insecure. Replace with SSH."})
                    elif port == 25:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "SMTP Open Relay Risk", "risk": "high", "cve": "CVE-2016-10033", "desc": "SMTP may allow open relay or spoofing if misconfigured."})

                    elif port == 53:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "DNS Amplification Risk", "risk": "high", "cve": "CVE-2013-5211", "desc": "Open DNS resolver can be used for DDoS amplification."})
                    
                    elif port == 110:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "POP3 Plaintext Auth", "risk": "high", "cve": "INFO-POP3", "desc": "POP3 transmits credentials in plaintext."})
                    
                    elif port == 143:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "IMAP Plaintext Auth", "risk": "high", "cve": "INFO-IMAP", "desc": "IMAP without SSL exposes credentials."})
                    
                    elif port == 139:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "NetBIOS Exposure", "risk": "high", "cve": "CVE-1999-0519", "desc": "NetBIOS can leak sensitive system information."})
                    
                    elif port == 389:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "LDAP Anonymous Bind", "risk": "high", "cve": "CVE-2017-8563", "desc": "LDAP may allow anonymous data access."})
                    
                    elif port == 5900:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "VNC Unauthenticated Access", "risk": "critical", "cve": "CVE-2019-15681", "desc": "VNC may allow remote access without strong authentication."})
                    
                    elif port == 6379:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Redis Unauthorized Access", "risk": "critical", "cve": "CVE-2022-0543", "desc": "Redis exposed without authentication can lead to RCE."})
                    
                    elif port == 27017:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "MongoDB Open Access", "risk": "critical", "cve": "CVE-2017-16137", "desc": "MongoDB exposed without auth can leak/modify data."})
                    
                    elif port == 8080:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Insecure Web Service", "risk": "medium", "cve": "INFO-HTTP-ALT", "desc": "Alternate HTTP port may expose admin panels or APIs."})
                    
                    elif port == 8443:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Weak HTTPS Config", "risk": "medium", "cve": "INFO-TLS", "desc": "Check for weak TLS versions or misconfiguration."})
                    
                    elif port == 9200:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Elasticsearch खुला है", "risk": "critical", "cve": "CVE-2015-1427", "desc": "Elasticsearch without auth allows data exposure and RCE."})
                    
                    elif port == 5601:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Kibana Dashboard Exposed", "risk": "high", "cve": "INFO-KIBANA", "desc": "Kibana exposed can leak logs and internal data."})
                    
                    elif port == 8888:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Jupyter Notebook Exposed", "risk": "high", "cve": "CVE-2019-10255", "desc": "Jupyter without auth can allow remote code execution."})
                    
                    elif port == 2049:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "NFS खुला है", "risk": "high", "cve": "CVE-1999-0170", "desc": "NFS can expose file systems to unauthorized users."})
                    
                    elif port == 1521:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "Oracle DB Exposed", "risk": "critical", "cve": "CVE-2012-1675", "desc": "Oracle DB listener vulnerable to remote attacks."})
                    
                    elif port == 7001:
                        seen_vulns.add(port)
                        vulnerabilities.append({"title": "WebLogic RCE Risk", "risk": "critical", "cve": "CVE-2020-14882", "desc": "Oracle WebLogic vulnerable to remote code execution."})

    risk_score, risk_label = calculate_risk(ports_data)
    open_count     = sum(1 for p in ports_data if p["state"] == "open")
    filtered_count = sum(1 for p in ports_data if p["state"] == "filtered")
    firewall_detected = filtered_count > open_count

    return jsonify({
        "ports":             ports_data,
        "vulnerabilities":   vulnerabilities,
        "risk_score":        risk_score,
        "risk_label":        risk_label,
        "firewall_detected": firewall_detected,
        "os_info":           os_info,    # ← NEW: None if not detected / not OS scan
    })


# RUN SERVER
if __name__ == '__main__':
    print("\n" + "=" * 55)
    print("  INVAT — Network Vulnerability Assessment Tool")
    
    # Allows Render deployment dynamic PORT environment hooking via gunicorn/direct run
    port = int(os.environ.get("PORT", 5000))
    print(f"  Open browser at: http://127.0.0.1:{port}")
    print("=" * 55 + "\n")
    
    app.run(host='0.0.0.0', port=port, debug=False)