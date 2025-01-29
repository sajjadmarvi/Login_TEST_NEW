from flask import Flask, render_template, request, redirect, flash, session, jsonify, url_for
import os
import json
import bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_socketio import SocketIO, emit
from celery import Celery
import boto3
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime, timedelta
import telebot
import threading
import secrets

app = Flask(__name__)
app.config.from_object('config.DevelopmentConfig' if os.environ.get('FLASK_ENV') == 'development' else 'config.ProductionConfig')
app.secret_key = 'your_secret_key_here'

# Initialize extensions
socketio = SocketIO(app)

# Initialize Limiter with In-Memory storage
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    storage_uri="memory://"
)

# Configure logging
handler = RotatingFileHandler('app.log', maxBytes=10000, backupCount=3)
handler.setLevel(logging.INFO)
app.logger.addHandler(handler)

# Initialize Celery
def make_celery(app):
    celery = Celery(app.import_name, backend=app.config['CELERY_RESULT_BACKEND'],
                    broker=app.config['CELERY_BROKER_URL'])
    celery.conf.update(app.config)
    return celery

celery = make_celery(app)

# Telegram Bot Token and ID
TELEGRAM_BOT_TOKEN = '8000764348:AAEytputhjTO8Sp7QA939fUCm8ja6YQI23I'
TELEGRAM_BOT_ID = '@Koshole_grooh_bot'
TELEGRAM_USER_ID = 167514573
bot = telebot.TeleBot(TELEGRAM_BOT_TOKEN)

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def upload_to_s3(file_name, bucket, object_name=None):
    if object_name is None:
        object_name = file_name
    s3 = boto3.client('s3', aws_access_key_id=app.config['AWS_ACCESS_KEY'],
                      aws_secret_access_key=app.config['AWS_SECRET_KEY'])
    try:
        s3.upload_file(file_name, bucket, object_name)
    except Exception as e:
        app.logger.error(f"Error uploading to S3: {e}")
        return False
    return True

# Load and save data to JSON file
def load_data():
    if os.path.exists('data.json'):
        try:
            with open('data.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            print("Corrupted data.json file. Creating a new one.")
            default_data = {'users': [], 'password_reset_tokens': {}, 'recovery_requests': []}
            save_data(default_data)
            return default_data
    return {'users': [], 'password_reset_tokens': {}, 'recovery_requests': []}

def save_data(data):
    with open('data.json', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)

def backup_data():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_filename = f"backup_data_{timestamp}.json"
    data = load_data()
    with open(backup_filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
    return backup_filename

# Load and save IP limits
def load_ip_limits():
    if os.path.exists('ip_limits.json'):
        try:
            with open('ip_limits.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_ip_limits(ip_limits):
    with open('ip_limits.json', 'w', encoding='utf-8') as f:
        json.dump(ip_limits, f, indent=4)

# Load and save user limits
def load_user_limits():
    if os.path.exists('user_limits.json'):
        try:
            with open('user_limits.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return {}
    return {}

def save_user_limits(user_limits):
    with open('user_limits.json', 'w', encoding='utf-8') as f:
        json.dump(user_limits, f, indent=4)

# Log user actions and send to Telegram
def log_action(username, ip_address, action):
    log_entry = {
        'username': username,
        'ip_address': ip_address,
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'action': action
    }
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    logs.append(log_entry)
    with open('logs.json', 'w', encoding='utf-8') as file:
        json.dump(logs, file, indent=4)
    
    try:
        message = f"📝 *New Log Entry*\n\n👤 *Username*: {username}\n🌐 *IP Address*: {ip_address}\n⏰ *Timestamp*: {log_entry['timestamp']}\n🔧 *Action*: {action}"
        bot.send_message(TELEGRAM_USER_ID, message, parse_mode='Markdown')
    except Exception as e:
        app.logger.error(f"Error sending log to Telegram: {e}")

# Load and save chat messages
def load_chat_messages():
    if os.path.exists('chat_messages.json'):
        try:
            with open('chat_messages.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_chat_messages(messages):
    with open('chat_messages.json', 'w', encoding='utf-8') as f:
        json.dump(messages, f, indent=4)

# Load and save password recovery requests
def load_recovery_requests():
    if os.path.exists('recovery_requests.json'):
        try:
            with open('recovery_requests.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError:
            return []
    return []

def save_recovery_requests(requests):
    with open('recovery_requests.json', 'w', encoding='utf-8') as f:
        json.dump(requests, f, indent=4)

# Generate a secure token for password reset
def generate_password_reset_token(username):
    token = secrets.token_urlsafe(32)
    data = load_data()
    if 'password_reset_tokens' not in data:
        data['password_reset_tokens'] = {}
    data['password_reset_tokens'][token] = {
        'username': username,
        'expires': (datetime.now() + timedelta(hours=1)).isoformat()
    }
    save_data(data)
    return token

# Send password reset link via Telegram
def send_password_reset_link(telegram_id, reset_link):
    try:
        message = f"برای بازیابی رمز عبور خود، روی لینک زیر کلیک کنید:\n{reset_link}\n\nاگر ربات را استارت نکرده‌اید، ابتدا ربات را از طریق لینک زیر استارت کنید:\nhttps://t.me/{TELEGRAM_BOT_ID}"
        bot.send_message(telegram_id, message)
        return True
    except Exception as e:
        app.logger.error(f"Error sending message via Telegram: {e}")
        return False

# اضافه کردن محدودیت‌ها به دیتا
def add_limit(key, limit_type):
    if limit_type == 'ip':
        limits = load_ip_limits()
    elif limit_type == 'user':
        limits = load_user_limits()
    else:
        return

    if key not in limits:
        limits[key] = {'attempts': 0, 'last_attempt': None, 'limit_until': None}
    
    limits[key]['attempts'] += 1
    limits[key]['last_attempt'] = datetime.now().isoformat()
    
    if limit_type == 'ip':
        if limits[key]['attempts'] >= 20:
            limits[key]['limit_until'] = (datetime.now() + timedelta(minutes=1)).isoformat()
    elif limit_type == 'user':
        data = load_data()
        user = next((u for u in data['users'] if u['username'] == key), None)
        if user:
            max_attempts = user.get('max_attempts', 3)
            if limits[key]['attempts'] >= max_attempts:
                limits[key]['limit_until'] = (datetime.now() + timedelta(hours=1)).isoformat()
    
    if limit_type == 'ip':
        save_ip_limits(limits)
    elif limit_type == 'user':
        save_user_limits(limits)

    if limits[key]['attempts'] >= 3:
        try:
            message = f"⚠️ *Rate Limit Alert*\n\n🔑 *Key*: {key}\n📊 *Attempts*: {limits[key]['attempts']}\n⏰ *Last Attempt*: {limits[key]['last_attempt']}\n🚫 *Limit Until*: {limits[key]['limit_until']}"
            bot.send_message(TELEGRAM_USER_ID, message, parse_mode='Markdown')
        except Exception as e:
            app.logger.error(f"Error sending rate limit alert to Telegram: {e}")

# بررسی محدودیت‌ها
def check_limit(key, limit_type):
    if limit_type == 'ip':
        limits = load_ip_limits()
    elif limit_type == 'user':
        limits = load_user_limits()
    else:
        return False

    if key in limits:
        limit = limits[key]
        if limit['limit_until'] and datetime.fromisoformat(limit['limit_until']) > datetime.now():
            return True
    return False

# پاک کردن محدودیت‌ها
def clear_limit(key, limit_type):
    if limit_type == 'ip':
        limits = load_ip_limits()
    elif limit_type == 'user':
        limits = load_user_limits()
    else:
        return

    if key in limits:
        del limits[key]
        if limit_type == 'ip':
            save_ip_limits(limits)
        elif limit_type == 'user':
            save_user_limits(limits)

# ارسال گزارش به ربات تلگرام
def send_telegram_alert(message):
    try:
        bot.send_message(TELEGRAM_USER_ID, message, parse_mode='Markdown')
    except Exception as e:
        app.logger.error(f"Error sending Telegram alert: {e}")

# Routes
@app.route('/')
def login():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
@limiter.limit("20 per minute")
def do_login():
    username = request.form['username']
    password = request.form['password']
    ip_address = request.remote_addr
    data = load_data()

    user = next((u for u in data['users'] if u['username'] == username), None)
    if user and check_limit(username, 'user'):
        flash('You are temporarily locked out. Please try again later.', 'danger')
        return redirect('/')

    if check_limit(ip_address, 'ip'):
        flash('Your IP is temporarily locked out. Please try again later.', 'danger')
        return redirect('/')

    if user and check_password(password, user['password']):
        session['username'] = user['username']
        session['role'] = user['role']
        session['avatar'] = user.get('avatar', 'default_avatar.png')
        log_action(username, ip_address, "Successful Login")
        flash('Login successful!', 'success')
        if user['role'] == 'admin':
            return redirect('/mrhjf')
        return redirect('/chat')
    else:
        add_limit(username, 'user')
        add_limit(ip_address, 'ip')
        log_action(username, ip_address, "Failed Login Attempt")
        flash('Invalid username or password', 'danger')
        return redirect('/')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        telegram_id = request.form['telegram_id']
        avatar = request.form.get('avatar', 'default_avatar.png')
        
        if password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect('/signup')
        
        data = load_data()
        if any(u['username'] == username for u in data['users']):
            flash('Username already exists!', 'danger')
            return redirect('/signup')
        
        verification_code = secrets.token_hex(3)
        try:
            bot.send_message(telegram_id, f"Your verification code is: {verification_code}")
        except Exception as e:
            app.logger.error(f"Error sending verification code to Telegram: {e}")
            flash('Error sending verification code. Please check your Telegram ID.', 'danger')
            return redirect('/signup')
        
        session['verification_code'] = verification_code
        session['signup_data'] = {
            'username': username,
            'password': hash_password(password),
            'telegram_id': telegram_id,
            'avatar': avatar,
            'role': 'user',
            'max_attempts': 3
        }
        
        return redirect('/verify_telegram')
    return render_template('signup.html')

@app.route('/signup_guide')
def signup_guide():
    return render_template('signup_guide.html')

@app.route('/verify_telegram', methods=['GET', 'POST'])
def verify_telegram():
    if request.method == 'POST':
        user_code = request.form['verification_code']
        if 'verification_code' in session and user_code == session['verification_code']:
            data = load_data()
            data['users'].append(session['signup_data'])
            save_data(data)
            log_action(session['signup_data']['username'], request.remote_addr, "New User Signup")
            flash('Account created successfully! Please log in.', 'success')
            session.pop('verification_code', None)
            session.pop('signup_data', None)
            return redirect('/')
        else:
            flash('Invalid verification code', 'danger')
    return render_template('verify_telegram.html')

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        username = request.form['username']
        data = load_data()
        user = next((u for u in data['users'] if u['username'] == username), None)
        if user:
            token = generate_password_reset_token(username)
            reset_link = url_for('reset_password', token=token, _external=True)
            
            send_password_reset_link(user['telegram_id'], reset_link)
            
            recovery_request = {
                'username': username,
                'telegram_id': user['telegram_id'],
                'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            recovery_requests = load_recovery_requests()
            recovery_requests.append(recovery_request)
            save_recovery_requests(recovery_requests)
            
            flash(f'A password reset link has been sent to your Telegram ID: {user["telegram_id"]}', 'success')
        else:
            flash('Invalid username', 'danger')
        return redirect('/forgot_password')
    return render_template('forgot_password.html')

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    data = load_data()
    token_data = data['password_reset_tokens'].get(token)
    
    if not token_data or datetime.fromisoformat(token_data['expires']) < datetime.now():
        flash('Invalid or expired token', 'danger')
        return redirect('/forgot_password')
    
    if request.method == 'POST':
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']
        
        if new_password != confirm_password:
            flash('Passwords do not match!', 'danger')
            return redirect(url_for('reset_password', token=token))
        
        user = next((u for u in data['users'] if u['username'] == token_data['username']), None)
        if user:
            user['password'] = hash_password(new_password)
            save_data(data)
            del data['password_reset_tokens'][token]
            save_data(data)
            flash('Your password has been reset successfully!', 'success')
            return redirect('/')
    
    return render_template('reset_password.html', token=token)

@app.route('/chat')
def chat():
    if 'username' not in session:
        return redirect('/')
    return render_template('chat.html', username=session['username'], avatar=session.get('avatar', 'default_avatar.png'))

@app.route('/success')
def success():
    if 'username' not in session:
        return redirect('/')
    return render_template('success.html', ip_address=request.remote_addr)

@app.route('/logout')
def logout():
    log_action(session.get('username'), request.remote_addr, "Logout")
    session.clear()
    return redirect('/')

# Admin Routes
@app.route('/mrhjf')
def mrhjf():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template('admin.html')

@app.route('/mrhjf/logs')
def mrhjf_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    return render_template('logs.html', logs=logs)

@app.route('/mrhjf/reports')
def mrhjf_reports():
    if session.get('role') != 'admin':
        return redirect('/')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    total_logins = len(logs)
    failed_logins = len([log for log in logs if log['action'] != "Successful Login"])
    unique_ips = len(set(log['ip_address'] for log in logs))
    return render_template('reports.html', total_logins=total_logins, failed_logins=failed_logins, unique_ips=unique_ips)

@app.route('/mrhjf/access_control')
def mrhjf_access_control():
    if session.get('role') != 'admin':
        return redirect('/')
    data = load_data()
    return render_template('access_control.html', users=data['users'])

@app.route('/mrhjf/update_access', methods=['POST'])
def mrhjf_update_access():
    if session.get('role') != 'admin':
        return redirect('/')
    username = request.form.get('username')
    role = request.form.get('role')
    password = request.form.get('password')
    max_attempts = request.form.get('max_attempts')
    avatar = request.form.get('avatar', 'default_avatar.png')
    data = load_data()
    user = next((u for u in data['users'] if u['username'] == username), None)
    if user:
        user['role'] = role
        if password:
            user['password'] = hash_password(password)
        if max_attempts:
            user['max_attempts'] = int(max_attempts)
        user['avatar'] = avatar
        save_data(data)
        log_action(session.get('username'), request.remote_addr, f"Updated Access for {username}")
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/add_user', methods=['POST'])
def add_user():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    username = request.form.get('username')
    password = request.form.get('password')
    telegram_id = request.form.get('telegram_id')
    role = request.form.get('role')
    max_attempts = request.form.get('max_attempts')
    avatar = request.form.get('avatar', 'default_avatar.png')
    
    data = load_data()
    if any(u['username'] == username for u in data['users']):
        flash('Username already exists!', 'danger')
        return redirect('/mrhjf/access_control')
    
    new_user = {
        'username': username,
        'password': hash_password(password),
        'telegram_id': telegram_id,
        'role': role,
        'max_attempts': int(max_attempts),
        'avatar': avatar
    }
    data['users'].append(new_user)
    save_data(data)
    log_action(session.get('username'), request.remote_addr, f"Added new user: {username}")
    flash('User added successfully!', 'success')
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/delete_user', methods=['POST'])
def delete_user():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    username = request.form.get('username')
    data = load_data()
    data['users'] = [u for u in data['users'] if u['username'] != username]
    save_data(data)
    log_action(session.get('username'), request.remote_addr, f"Deleted user: {username}")
    flash('User deleted successfully!', 'success')
    return redirect('/mrhjf/access_control')

@app.route('/mrhjf/search_logs')
def mrhjf_search_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    query = request.args.get('query', '')
    logs = []
    if os.path.exists('logs.json'):
        with open('logs.json', 'r', encoding='utf-8') as file:
            logs = json.load(file)
    
    filtered_logs = [
        log for log in logs 
        if (log.get('username') and query.lower() in log['username'].lower()) or 
           (log.get('ip_address') and query.lower() in log['ip_address'].lower())
    ]
    
    return render_template('search_logs.html', logs=filtered_logs, query=query)

@app.route('/mrhjf/real_time_logs')
def mrhjf_real_time_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template('real_time_logs.html')

@app.route('/mrhjf/chat_logs')
def mrhjf_chat_logs():
    if session.get('role') != 'admin':
        return redirect('/')
    chat_messages = load_chat_messages()
    return render_template('chat_logs.html', chat_messages=chat_messages)

@app.route('/mrhjf/real_time_chat')
def mrhjf_real_time_chat():
    if session.get('role') != 'admin':
        return redirect('/')
    return render_template('real_time_chat.html')

@app.route('/mrhjf/recovery_requests')
def mrhjf_recovery_requests():
    if session.get('role') != 'admin':
        return redirect('/')
    recovery_requests = load_recovery_requests()
    return render_template('recovery_requests.html', recovery_requests=recovery_requests)

@app.route('/mrhjf/view_decoded_passwords', methods=['POST'])
def view_decoded_passwords():
    if session.get('role') != 'admin':
        return redirect('/')
    full_admin_password = request.form.get('full_admin_password')
    if full_admin_password != 'alireza@9931':
        flash('Invalid full admin password', 'danger')
        return redirect('/mrhjf/access_control')
    
    data = load_data()
    decoded_passwords = []
    for user in data['users']:
        decoded_passwords.append({
            'username': user['username'],
            'password': user['password']
        })
    return render_template('decoded_passwords.html', passwords=decoded_passwords)

@app.route('/mrhjf/backup', methods=['POST'])
def backup():
    if session.get('role') != 'admin':
        return redirect('/')
    backup_filename = backup_data()
    log_action(session.get('username'), request.remote_addr, f"Backup created: {backup_filename}")
    flash(f'Backup created successfully: {backup_filename}', 'success')
    return redirect('/mrhjf')

# WebSocket for chat
@socketio.on('send_message')
def handle_send_message(data):
    username = session.get('username')
    recipient = data.get('recipient')
    message = data.get('message')
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    avatar = session.get('avatar', 'default_avatar.png')
    
    if username and recipient and message:
        chat_message = {
            'sender': username,
            'recipient': recipient,
            'message': message,
            'timestamp': timestamp,
            'avatar': avatar
        }
        messages = load_chat_messages()
        messages.append(chat_message)
        save_chat_messages(messages)
        
        emit('receive_message', chat_message, broadcast=True)

# WebSocket for online users
online_users = {}

@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        online_users[username] = request.sid
        emit('update_online_users', [{'username': username, 'avatar': session.get('avatar', 'default_avatar.png')}], broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    username = session.get('username')
    if username and username in online_users:
        del online_users[username]
        emit('update_online_users', list(online_users.keys()), broadcast=True)

@socketio.on('request_online_users')
def handle_request_online_users():
    emit('update_online_users', [{'username': username, 'avatar': session.get('avatar', 'default_avatar.png')} for username in online_users.keys()])

# New Routes for IP and User Limits
@app.route('/mrhjf/ip_limits')
def mrhjf_ip_limits():
    if session.get('role') != 'admin':
        return redirect('/')
    ip_limits = load_ip_limits()
    return render_template('ip_limits.html', ip_limits=ip_limits)

@app.route('/mrhjf/user_limits')
def mrhjf_user_limits():
    if session.get('role') != 'admin':
        return redirect('/')
    user_limits = load_user_limits()
    return render_template('user_limits.html', user_limits=user_limits)

@app.route('/mrhjf/clear_limit', methods=['POST'])
def mrhjf_clear_limit():
    if session.get('role') != 'admin':
        return redirect('/')
    
    key = request.form.get('key')
    limit_type = request.form.get('limit_type')
    
    if not key or not limit_type:
        flash('Invalid key or limit type', 'danger')
        return redirect('/mrhjf')
    
    clear_limit(key, limit_type)
    
    flash('Limit cleared successfully!', 'success')
    
    if limit_type == 'ip':
        return redirect(url_for('mrhjf_ip_limits'))
    elif limit_type == 'user':
        return redirect(url_for('mrhjf_user_limits'))
    else:
        return redirect('/mrhjf')

# New Route for getting chat history
@app.route('/mrhjf/get_chat_history')
def get_chat_history():
    username = request.args.get('username')
    if not username:
        return jsonify([])
    
    chat_messages = load_chat_messages()
    user_messages = [msg for msg in chat_messages if msg['sender'] == username or msg['recipient'] == username]
    return jsonify(user_messages)

# New Route for viewing chat history
@app.route('/mrhjf/chat_history')
def mrhjf_chat_history():
    if session.get('role') != 'admin':
        return redirect('/')
    username = request.args.get('username')
    return render_template('chat_history.html', username=username)

if __name__ == '__main__':
    # Create admin user if not exists
    data = load_data()
    if not any(u['username'] == 'Alireza_jf' for u in data['users']):
        admin_user = {
            'username': 'Alireza_jf',
            'password': hash_password('mrhjf5780'),
            'telegram_id': 'admin_telegram_id',
            'role': 'admin',
            'max_attempts': 3,
            'avatar': 'default_avatar.png'
        }
        data['users'].append(admin_user)
        save_data(data)
        print("Admin user created with username: Alireza_jf and password: mrhjf5780")

    socketio.run(app, debug=True, host='0.0.0.0', port=3000)
