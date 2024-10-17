from flask import Flask, render_template, request, redirect, url_for, flash, session, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import scapy.all as scapy
import nmap
import requests
from sqlalchemy.exc import OperationalError
from bs4 import BeautifulSoup
import os
import subprocess  # Make sure to import subprocess

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+mysqlconnector://root:@localhost/pen_test_toolkit'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key'
db = SQLAlchemy(app)

# Manually add Nmap directory to PATH
nmap_path = r"C:\Program Files (x86)\Nmap"
os.environ['PATH'] += os.pathsep + nmap_path

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    contact_hash = db.Column(db.String(255))
    email_hash = db.Column(db.String(255), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    created_at = db.Column(db.DateTime, default=db.func.current_timestamp())

class ScanResult(db.Model):
    __tablename__ = 'scan_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)
    target = db.Column(db.String(255), nullable=False)
    results = db.Column(db.Text, nullable=False)
    scan_date = db.Column(db.DateTime, default=db.func.current_timestamp())
    user = db.relationship('User', backref=db.backref('scan_results', lazy=True))

@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        g.user = User.query.get(session['user_id'])

@app.route('/')
def home():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form['first_name']
        last_name = request.form['last_name']
        username = request.form['username']
        contact = request.form['contact']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('register'))

        password_hash = generate_password_hash(password)
        contact_hash = generate_password_hash(contact)
        email_hash = generate_password_hash(email)

        new_user = User(
            first_name=first_name,
            last_name=last_name,
            username=username,
            contact_hash=contact_hash,
            email_hash=email_hash,
            password_hash=password_hash
        )
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful! You can now log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password_hash, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('profile'))
        else:
            flash('Invalid username or password', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        flash('Please log in to view your profile.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        user.first_name = request.form['first_name']
        user.last_name = request.form['last_name']
        user.username = request.form['username']
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=user)

@app.route('/edit_profile')
def edit_profile():
    if 'user_id' not in session:
        flash('Please log in to edit your profile.', 'danger')
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    return render_template('edit_profile.html', user=user)

def scapy_scan(network_range):
    packet = scapy.ARP(pdst=network_range)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet_broadcast = broadcast / packet
    result = scapy.srp(packet_broadcast, timeout=2, verbose=0)[0]
    clients = []

    for sent, received in result:
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})

    return clients

def nmap_scan(network_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=network_range, arguments='-sn')
    hosts_list = [(x, nm[x]['addresses'].get('mac', 'N/A')) for x in nm.all_hosts()]
    return hosts_list

@app.route('/network_scan', methods=['GET', 'POST'])
def network_scan():
    scan_results = None
    if request.method == 'POST':
        network_range = request.form['network_range']
        scapy_results = scapy_scan(network_range)
        nmap_results = nmap_scan(network_range)
        scan_results = {
            'scapy': scapy_results,
            'nmap': nmap_results
        }

        if 'user_id' in session:
            user_id = session['user_id']
            results_str = f"Scapy Results: {', '.join(['IP: ' + c['ip'] + ', MAC: ' + c['mac'] for c in scapy_results])}\n"
            results_str += f"Nmap Results: {', '.join(['IP: ' + h[0] + ', MAC: ' + h[1] for h in nmap_results])}"
            scan_result = ScanResult(user_id=user_id, scan_type='Network', target=network_range, results=results_str)
            db.session.add(scan_result)
            db.session.commit()

    return render_template('network_scan.html', scan_results=scan_results)

@app.route('/web_scan', methods=['GET', 'POST'])
def web_scan():
    results = []
    if request.method == 'POST':
        url = request.form['url']
        results = run_vulnerability_scan(url)

        if 'user_id' in session:
            user_id = session['user_id']
            results_str = '; '.join(results)
            scan_result = ScanResult(user_id=user_id, scan_type='Web', target=url, results=results_str)
            db.session.add(scan_result)
            db.session.commit()

    return render_template('web_scan.html', results=results)

def run_vulnerability_scan(url):
    vulnerabilities = []
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        # Example vulnerability checks (extend as needed)
        if response.headers.get('X-Frame-Options') is None:
            vulnerabilities.append('Missing X-Frame-Options header')

        if response.headers.get('Content-Security-Policy') is None:
            vulnerabilities.append('Missing Content-Security-Policy header')

        # Example form check for XSS vulnerability
        forms = soup.find_all('form')
        for form in forms:
            if form.get('method', '').lower() == 'get':
                vulnerabilities.append('Form with GET method detected, potential for URL-based XSS')

    except requests.exceptions.RequestException as e:
        vulnerabilities.append(f'Error scanning URL: {e}')

    return vulnerabilities

def run_sqlmap(url):
    command = ['python', 'D:/sqlmap-master/sqlmap.py', '-u', url, '--batch']
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        output = result.stdout + result.stderr
    except Exception as e:
        output = str(e)
    return output

@app.route('/sql_injection', methods=['GET', 'POST'])
def sql_injection():
    results = []
    if request.method == 'POST':
        url = request.form.get('url')
        try:
            # Run sqlmap as a subprocess
            process = subprocess.Popen(
                ['python', 'D:/sqlmap-master/sqlmap-master/sqlmap.py', '-u', url, '--batch'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = process.communicate()
            if process.returncode == 0:
                results = stdout.decode('utf-8').splitlines()
            else:
                results = stderr.decode('utf-8').splitlines()

            # Save the results to the database
            save_scan_results('SQL Injection', url, '\n'.join(results))
        except OperationalError as e:
            results.append(f"Database error: {str(e)}")
        except Exception as e:
            results.append(f"An error occurred: {str(e)}")

    return render_template('sql_injection.html', results=results)

def save_scan_results(scan_type, target, results):
    from datetime import datetime

    try:
        scan_result = ScanResult(
            user_id=g.user.id,
            scan_type=scan_type,
            target=target,
            results=results,
            scan_date=datetime.now()
        )
        db.session.add(scan_result)
        db.session.commit()
    except OperationalError as e:
        print(f"Database error: {str(e)}")

@app.route('/scan_history')
def scan_history():
    if 'user_id' not in session:
        flash('Please log in to view your scan history.', 'danger')
        return redirect(url_for('login'))

    user_id = session['user_id']
    scan_results = ScanResult.query.filter_by(user_id=user_id).all()
    return render_template('scan_history.html', scan_results=scan_results)

@app.route('/test_db')
def test_db():
    try:
        db.session.execute('SELECT 1')
        return 'Database connection successful!'
    except Exception as e:
        return f'Database connection failed: {e}'

if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
