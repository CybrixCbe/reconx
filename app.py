import os
import json
import sqlite3
import re
import time
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, Response
import database
import scanner
import requests

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize database on startup
database.init_db()

# Middleware / Before Request checks
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please login to access this page.", "danger")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    from functools import wraps
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session or session['user_role'] not in roles:
                flash("Access denied: Insufficient permissions.", "danger")
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# Basic routing
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        action = request.form.get('action') # 'login' or 'register'
        
        if action == 'register':
            username = request.form.get('username')
            role = request.form.get('role', 'User')
            
            if len(password) < 6:
                flash("Password must be at least 6 characters.", "danger")
                return render_template('login.html')
                
            user_id = database.create_user(username, email, password, role)
            if user_id:
                database.log_activity(user_id, "User Registration", f"Registered username: {username} with role: {role}", request.remote_addr)
                session['otp_email'] = email
                session['otp_code'] = "123456"
                session['temp_user_id'] = user_id
                session['temp_username'] = username
                session['temp_role'] = role
                flash("Account registered! Please enter the 6-digit OTP code sent to your email to verify.", "success")
                return redirect(url_for('verify_otp_route'))
            else:
                flash("Email already registered.", "danger")
        else:
            user = database.verify_user(email, password)
            if user:
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['user_role'] = user['role']
                database.log_activity(user['id'], "User Login", f"Logged in from IP: {request.remote_addr}", request.remote_addr)
                flash(f"Welcome back, {user['username']}!", "success")
                if user['profile_completed'] == 0:
                    return redirect(url_for('profile_completion'))
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password.", "danger")
                
    return render_template('login.html')

@app.route('/verify-otp-auth', methods=['GET', 'POST'])
def verify_otp_route():
    if 'temp_user_id' not in session and 'otp_email' not in session:
        return redirect(url_for('login'))
        
    email = session.get('otp_email', '')
    masked_email = email
    parts = email.split('@')
    if len(parts) == 2:
        name, domain = parts
        masked_name = name[:2] + '*' * (len(name) - 2) if len(name) > 2 else name + '*'
        masked_email = f"{masked_name}@{domain}"

    if request.method == 'POST':
        otp = request.form.get('otp')
        if otp == "123456":
            session['user_id'] = session['temp_user_id']
            session['username'] = session['temp_username']
            session['user_role'] = session['temp_role']
            session.pop('temp_user_id', None)
            session.pop('temp_username', None)
            session.pop('temp_role', None)
            
            user = database.get_user_by_id(session['user_id'])
            if user and user['profile_completed'] == 1:
                flash("OTP verification successful!", "success")
                return redirect(url_for('dashboard'))
            else:
                flash("OTP verified! Please complete your security researcher profile.", "success")
                return redirect(url_for('profile_completion'))
        else:
            flash("Invalid OTP verification code. Try 123456.", "danger")
            
    return render_template('otp_verify.html', masked_email=masked_email)

@app.route('/profile-completion', methods=['GET', 'POST'])
@login_required
def profile_completion():
    user = database.get_user_by_id(session['user_id'])
    if user and user['profile_completed'] == 1:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        full_name = request.form.get('full_name', '').strip()
        purpose = request.form.get('purpose', 'User').strip()
        experience = request.form.get('experience', 'Beginner').strip()
        organization = request.form.get('organization', '').strip()
        
        if not full_name:
            flash("Full Name is required.", "danger")
            return render_template('profile_completion.html')
            
        database.complete_user_profile(session['user_id'], full_name, purpose, experience, organization)
        database.log_activity(session['user_id'], "Complete Profile", "Profile credentials completed.", request.remote_addr)
        flash("Researcher profile updated successfully! Welcome to ReconX.", "success")
        return redirect(url_for('dashboard'))
        
    return render_template('profile_completion.html')

@app.route('/logout')
def logout():
    user_id = session.get('user_id')
    if user_id:
        database.log_activity(user_id, "User Logout", "Logged out.", request.remote_addr)
    session.clear()
    flash("You have logged out.", "info")
    return redirect(url_for('index'))

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = database.get_user_by_email(email)
        if user:
            # Simulate OTP send
            session['otp_email'] = email
            session['otp_code'] = "123456" # For simplicity in testing
            flash("An OTP verification code 123456 has been sent to your email.", "success")
            return render_template('forgot_password.html', step='otp')
        else:
            flash("No account associated with that email.", "danger")
    return render_template('forgot_password.html', step='email')

@app.route('/verify-otp', methods=['POST'])
def verify_otp():
    otp = request.form.get('otp')
    if otp == "123456" and 'otp_email' in session:
        return render_template('forgot_password.html', step='reset')
    flash("Invalid OTP code.", "danger")
    return render_template('forgot_password.html', step='otp')

@app.route('/reset-password', methods=['POST'])
def reset_password():
    password = request.form.get('password')
    email = session.get('otp_email')
    if email:
        user = database.get_user_by_email(email)
        if user:
            database.update_user_password(user['id'], password)
            database.log_activity(user['id'], "Password Reset", "Password was reset via OTP verification.", request.remote_addr)
            session.pop('otp_email', None)
            session.pop('otp_code', None)
            flash("Password reset successfully. Please log in.", "success")
            return redirect(url_for('login'))
    flash("Session expired. Please try again.", "danger")
    return redirect(url_for('forgot_password'))

@app.route('/dashboard')
@login_required
def dashboard():
    stats = database.get_dashboard_stats(session['user_id'], is_admin=(session['user_role'] == 'Admin'))
    return render_template('dashboard.html', stats=stats, announcements=ANNOUNCEMENTS)

@app.route('/scan/stream')
@login_required
def scan_stream():
    target = request.args.get('target', '').strip()
    modules_str = request.args.get('modules', '')
    modules_list = [m.strip() for m in modules_str.split(',') if m.strip()]
    
    if not target:
        return jsonify({"error": "Target website or IP is required."}), 400
    if not modules_list:
        return jsonify({"error": "Please select at least one reconnaissance module."}), 400

    # Clean target string (remove http:// or https:// or paths or ports)
    clean_target = target
    if clean_target.startswith("http://"):
        clean_target = clean_target[7:]
    elif clean_target.startswith("https://"):
        clean_target = clean_target[8:]
    if "/" in clean_target:
        clean_target = clean_target.split("/")[0]
    if ":" in clean_target:
        clean_target = clean_target.split(":")[0]

    # Validate target syntax (is it a valid domain or IP?)
    domain_pattern = re.compile(
        r'^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*'
        r'([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z0-9])$'
    )
    ip_pattern = re.compile(
        r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
        r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    )
    if not (domain_pattern.match(clean_target) or ip_pattern.match(clean_target)):
        return jsonify({"error": "Invalid target format. Please provide a valid domain name or IP address."}), 400

    user_id = session.get('user_id')
    remote_addr = request.remote_addr

    # Check for duplicate scans in progress or run recently for same target/user
    recent_scans = database.get_scans_by_user(user_id)
    for s in recent_scans:
        if s['target'] == clean_target:
            try:
                scan_dt = datetime.datetime.strptime(s['timestamp'], "%Y-%m-%d %H:%M:%S")
                if (datetime.datetime.now() - scan_dt).total_seconds() < 10:
                    return jsonify({"error": f"A scan for {clean_target} was run very recently. Please wait a moment."}), 400
            except Exception:
                pass

    def event_generator():
        yield f"data: {json.dumps({'percent': 5, 'log': '[i] Starting diagnostics loop on target: ' + clean_target, 'status': 'info'})}\n\n"
        time.sleep(0.4)

        scan_results = {
            "target": clean_target,
            "scan_time": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "modules": {}
        }

        total_modules = len(modules_list)
        increment = 90.0 / total_modules if total_modules > 0 else 0
        current_percent = 5

        # 1. WHOIS Lookup
        if "whois" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Querying WHOIS registry database...', 'status': 'info'})}\n\n"
            try:
                w_data = scanner.run_whois_lookup(clean_target)
                scan_results["modules"]["whois"] = w_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] WHOIS Registry details retrieved.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] WHOIS retrieval failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 2. DNS Enumeration
        if "dns" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Resolving DNS query record types...', 'status': 'info'})}\n\n"
            try:
                d_data = scanner.run_dns_enumeration(clean_target)
                scan_results["modules"]["dns"] = d_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] DNS mapping resolves completed.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] DNS Query failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 3. IP Intelligence
        if "ip" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Locating IP geolocation & network owner details...', 'status': 'info'})}\n\n"
            try:
                ip_data = scanner.run_ip_intelligence(clean_target)
                scan_results["modules"]["ip"] = ip_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] IP hosting information loaded.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] IP details lookup failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 4. SSL/TLS Analysis
        if "ssl" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Requesting SSL certificate handshake...', 'status': 'info'})}\n\n"
            try:
                s_data = scanner.run_ssl_analysis(clean_target)
                scan_results["modules"]["ssl"] = s_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] SSL handshake checks complete.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] SSL checks failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 5. HTTP Headers Check
        if "headers" in modules_list or "clickjacking" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Requesting HTTP security headers and clickjacking details...', 'status': 'info'})}\n\n"
            try:
                h_data = scanner.run_http_headers_and_clickjacking(clean_target)
                scan_results["modules"]["headers"] = h_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] HTTP headers and Clickjacking checks completed.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Headers checks failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 6. Robots.txt & Sitemap
        if "robots" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Fetching robots.txt & sitemap.xml endpoints...', 'status': 'info'})}\n\n"
            try:
                # Resolve base URL first
                base_url = "https://" + clean_target
                r_data = scanner.run_robots_and_sitemap(clean_target, base_url)
                scan_results["modules"]["robots_sitemap"] = r_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] Robots and Site structure parsed.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Structure check failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 7. Technology Fingerprint
        if "tech" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Detecting server technologies and CMS signatures...', 'status': 'info'})}\n\n"
            try:
                body_text = ""
                try:
                    headers = {"User-Agent": "ReconX-Security-Scanner/1.0"}
                    base_url = "https://" + clean_target
                    resp = requests.get(base_url, timeout=3, headers=headers)
                    body_text = resp.text
                except Exception:
                    pass
                h_dict = scan_results["modules"]["headers"].get("headers", {}) if "headers" in scan_results["modules"] else {}
                t_data = scanner.run_technology_detection(clean_target, h_dict, body_text)
                scan_results["modules"]["tech"] = t_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] Web technology stack fingerprint complete.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Tech signature checks failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 8. Port Scanning (simulated)
        if "portscan" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Triggering simulated ports & services sweep...', 'status': 'info'})}\n\n"
            try:
                p_data = scanner.simulate_port_scanning(clean_target, "Quick")
                scan_results["modules"]["portscan"] = p_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] Port scanning sweep completed.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Port scan failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 9. Subdomain Enumeration (simulated)
        if "subdomains" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Querying simulated passive subdomains records...', 'status': 'info'})}\n\n"
            try:
                sub_data = scanner.simulate_subdomain_enumeration(clean_target)
                scan_results["modules"]["subdomains"] = sub_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] Subdomain enumeration mapping complete.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Subdomain queries failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # 10. Directory Discovery (simulated)
        if "directory" in modules_list:
            yield f"data: {json.dumps({'percent': int(current_percent), 'log': '[i] Fuzzing simulated directory exposure paths...', 'status': 'info'})}\n\n"
            try:
                dir_data = scanner.simulate_directory_discovery(clean_target)
                scan_results["modules"]["directory"] = dir_data
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[+] Directory Discovery completed successfully.', 'status': 'success'})}\n\n"
            except Exception as e:
                yield f"data: {json.dumps({'percent': int(current_percent + increment), 'log': '[-] Directory discovery failed: ' + str(e), 'status': 'error'})}\n\n"
            current_percent += increment

        # Finalizing Score
        yield f"data: {json.dumps({'percent': 95, 'log': '[i] Aggregating checks. Compiling final risk index...', 'status': 'info'})}\n\n"
        dns_info = scan_results["modules"].get("dns", {})
        ssl_info = scan_results["modules"].get("ssl", {})
        h_info = scan_results["modules"].get("headers", {})
        p_info = scan_results["modules"].get("portscan", {})
        
        risk_info = scanner.calculate_risk_score(dns_info, ssl_info, h_info, p_info)
        scan_results["risk_assessment"] = risk_info
        risk_score = risk_info["score"]

        # Commit to database
        try:
            scan_id = database.save_scan(
                user_id, 
                clean_target, 
                risk_score, 
                modules_list, 
                json.dumps(scan_results)
            )
            database.log_activity(
                user_id, 
                "Execute Scan", 
                f"Scanned: {clean_target} with risk score: {risk_score} (Scan ID: {scan_id})", 
                remote_addr
            )
            yield f"data: {json.dumps({'percent': 100, 'log': '[+] Scan completed. Report compiled successfully.', 'status': 'done', 'scan_id': scan_id, 'results': scan_results})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'percent': 100, 'log': '[-] Database write failed: ' + str(e), 'status': 'error'})}\n\n"

    return Response(event_generator(), mimetype='text/event-stream')

@app.route('/scan/start', methods=['POST'])
@login_required
def start_scan():
    # Keep route for tests or fallback redirects
    target = request.form.get('target', '').strip()
    modules = request.form.getlist('modules')
    if not target or not modules:
        return jsonify({"error": "Target and modules are required."}), 400
    try:
        results = scanner.run_recon_scan(target, modules)
        risk_score = results["risk_assessment"]["score"]
        scan_id = database.save_scan(session['user_id'], target, risk_score, modules, json.dumps(results))
        return jsonify({"status": "success", "scan_id": scan_id, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/history')
@login_required
def history():
    user_id = session['user_id']
    is_admin = session['user_role'] == 'Admin'
    
    if is_admin:
        scans = database.get_all_scans()
    else:
        scans = database.get_scans_by_user(user_id)
        
    return render_template('history.html', scans=scans)

@app.route('/scan/detail/<int:scan_id>')
@login_required
def scan_detail(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        flash("Scan not found.", "danger")
        return redirect(url_for('history'))
        
    # Security check: Non-admins cannot see other users' scans
    if session['user_role'] != 'Admin' and scan['user_id'] != session['user_id']:
        flash("Unauthorized access.", "danger")
        return redirect(url_for('history'))
        
    results = json.loads(scan['results_json'])
    return render_template('scan_detail.html', scan=scan, results=results)

@app.route('/scan/delete/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan_route(scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        return jsonify({"error": "Scan not found."}), 404
        
    if session['user_role'] != 'Admin' and scan['user_id'] != session['user_id']:
        return jsonify({"error": "Unauthorized access."}), 403
        
    database.delete_scan(scan_id)
    database.log_activity(session['user_id'], "Delete Scan", f"Deleted scan record: {scan_id} for target {scan['target']}", request.remote_addr)
    return jsonify({"status": "success"})

# AI Chat Assistant endpoint
@app.route('/api/chat', methods=['POST'])
@login_required
def chat_assistant():
    message = request.json.get('message', '').strip().lower()
    
    # Static responses based on keyword mapping for security education
    response = "I'm your ReconX Cybersecurity assistant. Ask me questions about SSL, HTTP headers, Clickjacking, or Ports!"
    
    if "header" in message:
        response = (
            "HTTP Security Headers protect websites from common web vulnerabilities. Major headers include:<br>"
            "1. <strong>Content-Security-Policy (CSP)</strong>: Restricts resources (JS/CSS) that can load, mitigating XSS.<br>"
            "2. <strong>Strict-Transport-Security (HSTS)</strong>: Forces browser to communicate only via HTTPS.<br>"
            "3. <strong>X-Frame-Options</strong>: Protects against Clickjacking attacks.<br>"
            "To set these headers, add them to your web server configurations (Nginx/Apache) or your backend framework response."
        )
    elif "clickjacking" in message:
        response = (
            "<strong>Clickjacking</strong> is an attack where a user is tricked into clicking on a link or button "
            "on another page when they think they are clicking on the top-level page. This is usually done using transparent iframes.<br><br>"
            "<strong>Mitigation:</strong><br>"
            "- Configure the HTTP header: <code>X-Frame-Options: SAMEORIGIN</code><br>"
            "- Or set CSP: <code>Content-Security-Policy: frame-ancestors 'self';</code>"
        )
    elif "ssl" in message or "tls" in message:
        response = (
            "<strong>SSL/TLS Certificate analysis</strong> checks whether traffic encrypted between browser and server is safe.<br>"
            "Issues include expired certificates, weak algorithms (e.g. SHA-1), or invalid domain names. Always use Let's Encrypt or similar CA "
            "to issue a free valid TLS certificate, and enforce TLS 1.3."
        )
    elif "port" in message or "nmap" in message:
        response = (
            "<strong>Port Scanning</strong> determines which services (like Web Servers, Databases, SSH) are open to the internet.<br>"
            "Leaving ports open like SSH (22), FTP (21), or Database ports increases your attack surface. You should protect open ports with "
            "firewalls, enforce IP whitelist restrictions, or disable password logins on SSH."
        )
    elif "risk" in message or "score" in message:
        response = (
            "The <strong>ReconX Risk Score</strong> is calculated out of 100 based on standard pen-testing metrics.<br>"
            "- <strong>90-100: Low Risk</strong> (Good security hygiene).<br>"
            "- <strong>70-89: Medium Risk</strong> (Some missing security headers or warning configs).<br>"
            "- <strong>45-69: High Risk</strong> (Unencrypted HTTP, expired SSL, or exposed admin endpoints).<br>"
            "- <strong>0-44: Critical Risk</strong> (Vulnerable to active exploitation)."
        )
    elif "hello" in message or "hi" in message:
        response = "Hello! I am your AI Security Assistant. Ask me any questions about your scan findings."
        
    return jsonify({"response": response})

# Admin Portal Routing
@app.route('/admin')
@login_required
@role_required(['Admin'])
def admin():
    conn = database.get_db_connection()
    users = conn.execute("SELECT id, username, email, role, created_at FROM users").fetchall()
    activity_logs = database.get_activity_logs(50)
    
    # Basic system indicators
    stats = {
        "total_users": len(users),
        "total_scans": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
        "system_status": "Healthy",
        "cpu_usage": "1.2%", # Mock indicators
        "mem_usage": "42 MB"
    }
    conn.close()
    
    return render_template('admin.html', users=users, logs=activity_logs, stats=stats)

@app.route('/admin/user/role/<int:user_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def update_user_role(user_id):
    new_role = request.form.get('role')
    if new_role not in ['User', 'Researcher', 'Admin']:
        flash("Invalid role assignment.", "danger")
        return redirect(url_for('admin'))
        
    conn = database.get_db_connection()
    conn.execute("UPDATE users SET role = ? WHERE id = ?", (new_role, user_id))
    conn.commit()
    conn.close()
    
    database.log_activity(session['user_id'], "Modify User Role", f"Changed User ID {user_id} role to {new_role}", request.remote_addr)
    flash(f"User role updated to {new_role} successfully.", "success")
    return redirect(url_for('admin'))

# Multi-Format Report Exporter Route
@app.route('/scan/export/<format_type>/<int:scan_id>')
@login_required
def export_report_endpoint(format_type, scan_id):
    scan = database.get_scan_by_id(scan_id)
    if not scan:
        flash("Scan report not found.", "danger")
        return redirect(url_for('dashboard'))
        
    # Check permissions
    if session['user_role'] != 'Admin' and scan['user_id'] != session['user_id']:
        flash("Unauthorized access to report.", "danger")
        return redirect(url_for('dashboard'))
        
    try:
        results = json.loads(scan['results_json'])
    except Exception:
        flash("Error parsing scan results payload.", "danger")
        return redirect(url_for('dashboard'))
        
    filename = f"reconx-report-{results.get('target', 'unknown')}"
    
    if format_type == 'json':
        response_data = json.dumps(results, indent=4)
        return Response(
            response_data,
            mimetype="application/json",
            headers={"Content-disposition": f"attachment; filename={filename}.json"}
        )
        
    elif format_type == 'txt':
        content = "========================================================\n"
        content += "          RECONX WEB SECURITY ASSESSMENT REPORT       \n"
        content += "========================================================\n"
        content += f"Target Domain: {results.get('target')}\n"
        content += f"Scan Executed: {results.get('scan_time')}\n"
        content += f"Security Rating: {results['risk_assessment'].get('score')}/100\n"
        content += f"Threat Level: {results['risk_assessment'].get('level')}\n"
        content += "========================================================\n\n"
        
        content += "--- EXECUTIVE SUMMARY FINDINGS ---\n"
        for r in results['risk_assessment'].get('reasons', []):
            content += f"- {r}\n"
            
        content += "\n--- MITIGATION RECOMMENDATIONS ---\n"
        for r in results['risk_assessment'].get('recommendations', []):
            content += f"- {r}\n"
            
        return Response(
            content,
            mimetype="text/plain",
            headers={"Content-disposition": f"attachment; filename={filename}.txt"}
        )
        
    elif format_type == 'csv':
        content = "Category,Parameter,Value\n"
        content += f"Metadata,Target,{results.get('target')}\n"
        content += f"Metadata,Scan Time,{results.get('scan_time')}\n"
        content += f"Rating,Score,{results['risk_assessment'].get('score')}\n"
        content += f"Rating,Level,{results['risk_assessment'].get('level')}\n"
        
        # Add WHOIS if exists
        whois_data = results.get("modules", {}).get("whois", {})
        if whois_data and whois_data.get("status") != "error":
            for k, v in whois_data.items():
                if k != "status":
                    content += f"WHOIS,{k},\"{str(v).replace('\"', '\"\"')}\"\n"
                    
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-disposition": f"attachment; filename={filename}.csv"}
        )
        
    elif format_type == 'md':
        content = f"# ReconX Security Assessment Report: `{results.get('target')}`\n\n"
        content += f"- **Scan Time:** {results.get('scan_time')}\n"
        content += f"- **Risk Rating:** {results['risk_assessment'].get('score')}/100\n"
        content += f"- **Threat Level:** {results['risk_assessment'].get('level')}\n\n"
        
        content += "## Executive Findings\n"
        for r in results['risk_assessment'].get('reasons', []):
            content += f"- {r}\n"
            
        content += "\n## Remediation Recommendations\n"
        for r in results['risk_assessment'].get('recommendations', []):
            content += f"- {r}\n"
            
        return Response(
            content,
            mimetype="text/markdown",
            headers={"Content-disposition": f"attachment; filename={filename}.md"}
        )
        
    elif format_type == 'html':
        html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ReconX Security Report - {results.get('target')}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        body {{ background: #080A12; color: #FFFFFF; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 40px 20px; }}
        .glass-card {{ background: rgba(17, 24, 39, 0.7); border: 1px solid rgba(0, 229, 255, 0.15); border-radius: 12px; padding: 30px; margin-bottom: 30px; }}
        .text-gradient {{ background: linear-gradient(135deg, #00E5FF 0%, #7C3AED 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .badge-danger {{ background: #FF5252; }}
        .badge-warning {{ background: #FFC107; color: #000; }}
        .badge-success {{ background: #00E676; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="glass-card text-center">
            <h1 class="text-gradient fw-bold mb-2">RECONX SECURITY ASSESSMENT</h1>
            <p class="text-muted">Target Domain: <strong>{results.get('target')}</strong> | Date: {results.get('scan_time')}</p>
        </div>
        
        <div class="row">
            <div class="col-md-4">
                <div class="glass-card text-center">
                    <h5 class="text-muted mb-3">Overall Security Rating</h5>
                    <h1 class="display-3 fw-bold text-info">{results['risk_assessment'].get('score')}</h1>
                    <span class="badge badge-warning py-2 px-3 mt-2">{results['risk_assessment'].get('level')} Threat Level</span>
                </div>
            </div>
            <div class="col-md-8">
                <div class="glass-card">
                    <h5 class="text-info mb-3">Executive Summary Findings</h5>
                    <ul>
                        {"".join(f"<li>{r}</li>" for r in results['risk_assessment'].get('reasons', []))}
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="glass-card">
            <h5 class="text-info mb-3">Remediation Guidelines</h5>
            <ol>
                {"".join(f"<li class='mb-2'>{r}</li>" for r in results['risk_assessment'].get('recommendations', []))}
            </ol>
        </div>
    </div>
</body>
</html>"""
        return Response(
            html_content,
            mimetype="text/html",
            headers={"Content-disposition": f"attachment; filename={filename}.html"}
        )
        
    flash("Unknown export format requested.", "danger")
    return redirect(url_for('dashboard'))

# System Announcements Cache
ANNOUNCEMENTS = [
    {"message": "Welcome to ReconX 3.0 Platform Rebuild!", "timestamp": "2026-07-23 05:45:00"},
    {"message": "Scheduled maintenance: Database backups completed.", "timestamp": "2026-07-22 18:00:00"}
]

# Mock OAuth Authentication Sandbox Endpoint
@app.route('/auth/oauth/<provider>')
def oauth_mock(provider):
    username = f"{provider}_researcher"
    email = f"{username}@reconx.local"
    
    user = database.get_user_by_email(email)
    if not user:
        user_id = database.create_user(username, email, "OAuthSecurePassword2026!", "Researcher")
        database.complete_user_profile(user_id, f"{provider.capitalize()} Researcher", "Bug Bounty", "Advanced", "OAuth Sandbox")
        user = database.get_user_by_id(user_id)
        
    session['user_id'] = user['id']
    session['username'] = user['username']
    session['user_role'] = user['role']
    database.log_activity(user['id'], "OAuth Login", f"Logged in via {provider.capitalize()} OAuth", request.remote_addr)
    flash(f"Logged in successfully via {provider.capitalize()}!", "success")
    return redirect(url_for('dashboard'))

# Admin Control: Delete User
@app.route('/admin/user/delete/<int:user_id>', methods=['POST'])
@login_required
@role_required(['Admin'])
def delete_user(user_id):
    if user_id == session['user_id']:
        flash("You cannot delete your own admin account.", "danger")
        return redirect(url_for('admin'))
        
    conn = database.get_db_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    database.log_activity(session['user_id'], "Delete User", f"Deleted User ID {user_id}", request.remote_addr)
    flash("User deleted successfully.", "success")
    return redirect(url_for('admin'))

# Admin Control: Announcements Broadcast
@app.route('/admin/announcement', methods=['POST'])
@login_required
@role_required(['Admin'])
def post_announcement():
    msg = request.form.get('message', '').strip()
    if msg:
        ANNOUNCEMENTS.insert(0, {
            "message": msg,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        })
        flash("Announcements broadcasted to all active operator feeds.", "success")
    return redirect(url_for('admin'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)
