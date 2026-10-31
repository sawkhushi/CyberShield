from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import os
import re
import urllib.parse
from datetime import datetime  # <--- Added to track when scans happen
import csv
from io import StringIO
from flask import Response
import socket
import requests
from urllib.parse import urlparse

app = Flask(__name__)

# --- App Configuration ---
app.config['SECRET_KEY'] = 'cybershield_super_secret_key_2026'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cybershield.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --- Database Models ---
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    # Link user to their logs
    logs = db.relationship('AuditLog', backref='user', lazy=True)

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    event_type = db.Column(db.String(100), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    status = db.Column(db.String(50), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# --- Public Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))

        hashed_pw = generate_password_hash(password, method='scrypt')
        new_user = User(name=name, email=email, password_hash=hashed_pw)
        db.session.add(new_user)
        db.session.commit()

        flash('Account created successfully! Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/reset', methods=['GET', 'POST'])
def reset_password():
    # If they are already logged in, send them to the dashboard
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        new_password = request.form.get('new_password')
        
        # Search the database for this email
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Email found! Hash the new password and update the database
            hashed_pw = generate_password_hash(new_password, method='scrypt')
            user.password_hash = hashed_pw
            db.session.commit()
            
            flash('Password reset successfully! You can now log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Email address not found in our system.', 'error')
            return redirect(url_for('reset_password'))

    return render_template('reset.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# --- Secure Internal Routes ---
@app.route('/dashboard')
@login_required
def dashboard():
    # 1. Get recent activity for the list (last 5 scans)
    recent_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).limit(5).all()
    
    # 2. Count total scans for the first card
    total_scans = AuditLog.query.filter_by(user_id=current_user.id).count()
    
    # 3. THE FIX: Count ONLY the logs marked as 'Critical' for the alert card
    critical_alerts = AuditLog.query.filter_by(user_id=current_user.id, status='Critical').count()
    
    return render_template('dashboard.html', 
                           user=current_user, 
                           logs=recent_logs,
                           recent_logs=recent_logs, 
                           total_scans=total_scans, 
                           critical_alerts=critical_alerts)

@app.route('/report')
@login_required
def report():
    # Fetch all logs for this specific user
    all_logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).all()
    return render_template('report.html', user=current_user, logs=all_logs)

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    account_status = "Active - No Restrictions"

    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')

        # Verify the current password before allowing a change
        if check_password_hash(current_user.password_hash, current_password):
            hashed_pw = generate_password_hash(new_password, method='scrypt')
            current_user.password_hash = hashed_pw
            db.session.commit()
            flash('Password successfully updated!', 'success')
        else:
            flash('Incorrect current password. Update failed.', 'error')
            
        return redirect(url_for('admin'))

    return render_template('admin.html', user=current_user, status=account_status)

@app.route('/export')
@login_required
def export_logs():
    # Fetch all logs for the current user
    logs = AuditLog.query.filter_by(user_id=current_user.id).order_by(AuditLog.timestamp.desc()).all()
    
    # Create a virtual file in memory
    si = StringIO()
    cw = csv.writer(si)
    
    # Write the column headers
    cw.writerow(['Timestamp', 'Event Type', 'Target Details', 'Status'])
    
    # Loop through the database and write each row
    for log in logs:
        cw.writerow([log.timestamp.strftime('%Y-%m-%d %H:%M:%S'), log.event_type, log.target, log.status])
        
    output = si.getvalue()
    
    # Send the file to the user's browser for download
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=CyberShield_Audit_{current_user.name}.csv"}
    )

@app.route('/password', methods=['GET', 'POST'])
@login_required
def password():
    score = None
    results = {}
    target_password = ""

    if request.method == 'POST':
        target_password = request.form.get('password_input', '')
        score = 0
        
        results['length'] = len(target_password) >= 12
        results['upper'] = bool(re.search(r'[A-Z]', target_password))
        results['lower'] = bool(re.search(r'[a-z]', target_password))
        results['num'] = bool(re.search(r'[0-9]', target_password))
        results['special'] = bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', target_password))
        
        for check in results.values():
            if check: score += 20
            
        # Log the event to the database!
        log_status = "Optimal" if score >= 80 else ("Warning" if score >= 40 else "Critical")
        new_log = AuditLog(user_id=current_user.id, event_type="Credential Scan", target=f"Length: {len(target_password)} chars", status=log_status)
        db.session.add(new_log)
        db.session.commit()

    return render_template('password.html', user=current_user, score=score, results=results, target=target_password)

import re

@app.route('/urlcheck', methods=['GET', 'POST'])
@login_required
def urlcheck():
    scan_result = None
    location_data = None
    target_url = None
    
    if request.method == 'POST':
        target_url = request.form.get('url_input') or request.form.get('url')
        
        if target_url:
            # --- REAL URL THREAT SCORING ENGINE ---
            score = 100
            
            # Penalty 1: Missing HTTPS (Data not encrypted)
            if not target_url.startswith("https://"):
                score -= 40
                
            # Penalty 2: Suspicious credential passing in URL
            if "@" in target_url:
                score -= 30
                
            # Penalty 3: Domain is a raw IP address (Common in phishing)
            try:
                domain = urlparse(target_url).netloc
                if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain):
                    score -= 30
            except:
                pass
                
            # Penalty 4: Unusually long URL (Obfuscation tactic)
            if len(target_url) > 85:
                score -= 15
                
            # Keep score within 0-100 bounds
            score = max(0, min(100, score))
            
            # Determine Status Label
            if score == 100:
                status = "Safe"
            elif score >= 60:
                status = "Suspicious"
            else:
                status = "Critical"
                
            scan_result = {"score": score, "status": status}
            # --------------------------------------
            
            # Log to Database
            new_log = AuditLog(
                user_id=current_user.id,
                event_type='URL Scan',
                target=target_url,
                status=scan_result['status']
            )
            db.session.add(new_log)
            db.session.commit()
            
            # Geolocation Lookup
            try:
                parsed = urlparse(target_url)
                domain_geo = parsed.netloc or parsed.path
                if domain_geo.startswith('www.'):
                    domain_geo = domain_geo[4:]
                    
                ip_address = socket.gethostbyname(domain_geo)
                geo_response = requests.get(f"http://ip-api.com/json/{ip_address}", timeout=3).json()
                
                if geo_response.get("status") == "success":
                    location_data = {
                        "ip": ip_address,
                        "country": geo_response.get("country"),
                        "city": geo_response.get("city"),
                        "isp": geo_response.get("isp")
                    }
            except Exception:
                pass

    return render_template('urlcheck.html', user=current_user, result=scan_result, location=location_data, target=target_url)

# --- Initialize Database ---
with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(port=5001, debug=True)

@app.route('/secret-db-view')
def secret_db_view():
    # Fetch all data from the database
    all_users = User.query.all()
    all_logs = AuditLog.query.all()
    
    # Format it cleanly
    user_data = [f"ID {u.id}: {u.email}" for u in all_users]
    log_data = [f"Log {l.id} (User {l.user_id}) | {l.target} | {l.status}" for l in all_logs]
    
    # Return as raw data to the browser
    return {
        "1_Live_Users": user_data,
        "2_Live_Scans": log_data,
        "3_Message": "Live Database Connection Successful"
    }