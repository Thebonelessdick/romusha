from flask import Flask, request, redirect, render_template, session, url_for, flash, send_from_directory
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import psycopg2
import random
import string
import os
from dotenv import load_dotenv
from urllib.parse import urlparse
from datetime import timedelta, datetime, date
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from redis import Redis
import certifi
import re

# Inisialisasi Flask
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')
if not app.secret_key:
    raise ValueError("SECRET_KEY must be set in environment variables")

# Konfigurasi sesi
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

# Filter Jinja2
@app.template_filter('split')
def split_filter(s, delimiter=None):
    return s.split(delimiter)

# Inisialisasi Bcrypt
bcrypt = Bcrypt(app)

# Konfigurasi Redis dan Flask-Limiter
redis_url = os.environ.get('HEROKU_REDIS_MAUVE_URL', 'redis://localhost:6379')
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri=redis_url,
    storage_options={"ssl_cert_reqs": None}  # Nonaktifkan verifikasi sertifikat
)

# Debugging koneksi Redis
try:
    redis_client = Redis.from_url(redis_url, ssl_cert_reqs=None)  # Nonaktifkan verifikasi sertifikat
    redis_client.ping()
    app.logger.info("Redis connection successful")
except Exception as e:
    app.logger.error(f"Redis connection failed: {e}")

load_dotenv()

# Fungsi untuk koneksi database
def get_db_connection():
    database_url = os.environ.get("DATABASE_URL")
    if database_url:
        if database_url.startswith("postgres://"):
            database_url = database_url.replace("postgres://", "postgresql://", 1)
        return psycopg2.connect(database_url)
    else:
        raise Exception("DATABASE_URL not set")

# Inisialisasi database
def init_db():
    try:
        conn = get_db_connection()
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users 
                    (id SERIAL PRIMARY KEY, username TEXT UNIQUE, password TEXT, email TEXT UNIQUE, 
                     last_ip TEXT, registered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, is_banned BOOLEAN DEFAULT FALSE)''')
        c.execute('''CREATE TABLE IF NOT EXISTS urls 
                    (short_code TEXT PRIMARY KEY, long_url TEXT, user_id INTEGER REFERENCES users(id), 
                     click_count INTEGER DEFAULT 0, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        c.execute('''CREATE TABLE IF NOT EXISTS clicks 
                    (id SERIAL PRIMARY KEY, short_code TEXT, click_date DATE, click_count INTEGER DEFAULT 0, 
                     CONSTRAINT fk_short_code FOREIGN KEY (short_code) REFERENCES urls(short_code) ON DELETE CASCADE)''')
        conn.commit()
    except Exception as e:
        app.logger.error(f"Error initializing database: {e}")
        conn.rollback()
    finally:
        conn.close()

init_db()

# Fungsi utilitas
def generate_short_code():
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(6))

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_admin():
    if 'user_id' not in session:
        return False
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = %s", (session['user_id'],))
    user = c.fetchone()
    conn.close()
    return user and user[0].lower() == "master"

@app.context_processor
def utility_processor():
    return dict(is_admin=is_admin)

# Fungsi untuk mengirim email
def send_email(to_email, new_password):
    sender_email = os.environ.get('EMAIL_SENDER')
    sender_password = os.environ.get('EMAIL_PASSWORD')
    if not sender_email or not sender_password:
        raise ValueError("EMAIL_SENDER and EMAIL_PASSWORD must be set in environment variables")

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = 'Password Baru untuk Akun Romusha Shortlink Anda'
    body = f"""
    Halo,
    Anda telah meminta pengaturan ulang password untuk akun Romusha Shortlink Anda.
    Password baru Anda: {new_password}
    Silakan login dan ubah password Anda di halaman profil jika diperlukan.
    Jika Anda tidak meminta ini, abaikan email ini.
    Terima kasih,
    Tim Romusha Shortlink
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        server.sendmail(sender_email, to_email, msg.as_string())
        server.quit()
        return True
    except Exception as e:
        app.logger.error(f"Failed to send email: {e}")
        return False

# Routes
@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per hour")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        ip_address = request.remote_addr
        app.logger.info(f"Login attempt: {username}, IP: {ip_address}")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, password, is_banned FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
        user = c.fetchone()
        if user:
            if user[2]:
                flash('Akun Anda telah dibanned!', 'danger')
            elif bcrypt.check_password_hash(user[1], password):
                c.execute("UPDATE users SET last_ip = %s WHERE id = %s", (ip_address, user[0]))
                conn.commit()
                session['user_id'] = user[0]
                session.permanent = True
                flash('Login berhasil!', 'success')
                if 'pending_url' in session:
                    long_url = session.pop('pending_url')
                    if not is_valid_url(long_url):
                        flash('URL tidak valid!', 'danger')
                        return redirect(url_for('dashboard'))
                    short_code = generate_short_code()
                    while True:
                        c.execute("SELECT short_code FROM urls WHERE short_code = %s", (short_code,))
                        if not c.fetchone():
                            break
                        short_code = generate_short_code()
                    c.execute("INSERT INTO urls (short_code, long_url, user_id) VALUES (%s, %s, %s)",
                              (short_code, long_url, session['user_id']))
                    conn.commit()
                    short_url = f"{request.host_url}{short_code}"
                    flash(f'Shortlink Anda: <a href="{short_url}" target="_blank">{short_url}</a>', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Password salah!', 'danger')
        else:
            flash('Username tidak ditemukan!', 'danger')
        conn.close()
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        ip_address = request.remote_addr

        if not all([username, email, password, confirm_password]):
            flash('Semua kolom harus diisi!', 'danger')
            return redirect(url_for('register'))
        if len(username) < 3 or len(username) > 20 or not username.isalnum():
            flash('Username harus 3-20 karakter, huruf dan angka saja!', 'danger')
            return redirect(url_for('register'))
        if '@' not in email or '.' not in email:
            flash('Email tidak valid!', 'danger')
            return redirect(url_for('register'))
        if len(password) < 6 or password != confirm_password:
            flash('Password minimal 6 karakter dan harus cocok dengan konfirmasi!', 'danger')
            return redirect(url_for('register'))

        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT username FROM users WHERE LOWER(username) = LOWER(%s)", (username,))
        if c.fetchone():
            flash('Username sudah digunakan!', 'danger')
        elif c.execute("SELECT email FROM users WHERE LOWER(email) = LOWER(%s)", (email,)) and c.fetchone():
            flash('Email sudah digunakan!', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            c.execute("INSERT INTO users (username, email, password, last_ip) VALUES (%s, %s, %s, %s) RETURNING id",
                      (username, email, hashed_password, ip_address))
            user_id = c.fetchone()[0]
            conn.commit()
            session['user_id'] = user_id
            session.permanent = True
            flash('Registrasi berhasil!', 'success')
            if 'pending_url' in session:
                long_url = session.pop('pending_url')
                if not is_valid_url(long_url):
                    flash('URL tidak valid!', 'danger')
                    return redirect(url_for('dashboard'))
                short_code = generate_short_code()
                while True:
                    c.execute("SELECT short_code FROM urls WHERE short_code = %s", (short_code,))
                    if not c.fetchone():
                        break
                    short_code = generate_short_code()
                c.execute("INSERT INTO urls (short_code, long_url, user_id) VALUES (%s, %s, %s)",
                          (short_code, long_url, session['user_id']))
                conn.commit()
                short_url = f"{request.host_url}{short_code}"
                flash(f'Shortlink Anda: <a href="{short_url}" target="_blank">{short_url}</a>', 'success')
            return redirect(url_for('dashboard'))
        conn.close()
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Anda telah logout.', 'success')
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT username FROM users WHERE id = %s", (session['user_id'],))
    user = c.fetchone()
    if not user:
        conn.close()
        return redirect(url_for('logout'))
    username = user[0]
    if request.method == 'POST':
        new_password = request.form['password'].strip()
        if not new_password:
            flash('Password baru tidak boleh kosong!', 'danger')
        else:
            hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
            c.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, session['user_id']))
            conn.commit()
            flash('Password berhasil diperbarui!', 'success')
    conn.close()
    return render_template('profile.html', username=username)

@app.route('/dashboard', methods=['GET', 'POST'])
@app.route('/dashboard/page/<int:page>', methods=['GET'])
def dashboard(page=1):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        long_url = request.form['url']
        short_code = request.form.get('short_code', '').strip()
        if not is_valid_url(long_url):
            flash('URL tidak valid!', 'danger')
            return redirect(url_for('dashboard', page=page))
        conn = get_db_connection()
        c = conn.cursor()
        if not short_code:
            short_code = generate_short_code()
            while True:
                c.execute("SELECT short_code FROM urls WHERE short_code = %s", (short_code,))
                if not c.fetchone():
                    break
                short_code = generate_short_code()
        else:
            if not short_code.isalnum() or len(short_code) < 3 or len(short_code) > 10:
                flash('Kode shortlink harus 3-10 karakter, huruf dan angka!', 'danger')
                conn.close()
                return redirect(url_for('dashboard', page=page))
            c.execute("SELECT short_code FROM urls WHERE short_code = %s", (short_code,))
            if c.fetchone():
                flash('Kode shortlink sudah digunakan!', 'danger')
                conn.close()
                return redirect(url_for('dashboard', page=page))
        c.execute("INSERT INTO urls (short_code, long_url, user_id) VALUES (%s, %s, %s)",
                  (short_code, long_url, session['user_id']))
        conn.commit()
        conn.close()
        short_url = f"{request.host_url}{short_code}"
        flash(f'Shortlink berhasil dibuat: <a href="{short_url}" target="_blank">{short_url}</a>', 'success')
        return redirect(url_for('dashboard', page=1))

    items_per_page = 10
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT COUNT(*) FROM urls WHERE user_id = %s", (session['user_id'],))
    total_items = c.fetchone()[0]
    total_pages = (total_items + items_per_page - 1) // items_per_page
    page = max(1, min(page, total_pages or 1))
    offset = (page - 1) * items_per_page
    c.execute("SELECT short_code, long_url, click_count FROM urls WHERE user_id = %s ORDER BY created_at DESC LIMIT %s OFFSET %s",
              (session['user_id'], items_per_page, offset))
    user_urls = c.fetchall()
    conn.close()
    return render_template('home.html', user_urls=user_urls, page=page, total_pages=total_pages)

@app.route('/delete/<short_code>/<int:page>')
@app.route('/delete/<short_code>')
def delete_url(short_code, page=1):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM urls WHERE short_code = %s AND user_id = %s", (short_code, session['user_id']))
    conn.commit()
    conn.close()
    flash('Shortlink berhasil dihapus!', 'success')
    return redirect(url_for('dashboard', page=page))

@app.route('/<short_code>')
def redirect_url(short_code):
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT long_url FROM urls WHERE short_code = %s", (short_code,))
    result = c.fetchone()
    if result:
        c.execute("UPDATE urls SET click_count = click_count + 1 WHERE short_code = %s", (short_code,))
        today = date.today()
        c.execute("SELECT click_count FROM clicks WHERE short_code = %s AND click_date = %s", (short_code, today))
        if c.fetchone():
            c.execute("UPDATE clicks SET click_count = click_count + 1 WHERE short_code = %s AND click_date = %s", (short_code, today))
        else:
            c.execute("INSERT INTO clicks (short_code, click_date, click_count) VALUES (%s, %s, %s)", (short_code, today, 1))
        conn.commit()
        conn.close()
        return redirect(result[0])
    conn.close()
    return "URL tidak ditemukan!", 404

@app.route('/reset_click/<short_code>/<int:page>')
def reset_click(short_code, page=1):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE urls SET click_count = 0 WHERE short_code = %s AND user_id = %s", (short_code, session['user_id']))
    c.execute("DELETE FROM clicks WHERE short_code = %s", (short_code,))
    conn.commit()
    conn.close()
    flash('Click count berhasil direset!', 'success')
    return redirect(url_for('dashboard', page=page))

@app.route('/update_url', methods=['POST'])
def update_url():
    if 'user_id' not in session:
        return {"success": False, "message": "Login diperlukan!"}, 401
    data = request.get_json()
    old_short_code = data.get('old_short_code')
    new_short_code = data.get('new_short_code')
    new_long_url = data.get('long_url')
    if not all([old_short_code, new_short_code, new_long_url]):
        return {"success": False, "message": "Data tidak lengkap!"}, 400
    if not is_valid_url(new_long_url):
        return {"success": False, "message": "URL tidak valid!"}, 400
    if not new_short_code.isalnum() or len(new_short_code) < 3 or len(new_short_code) > 10:
        return {"success": False, "message": "Kode shortlink harus 3-10 karakter, huruf dan angka!"}, 400
    conn = get_db_connection()
    c = conn.cursor()
    if new_short_code != old_short_code:
        c.execute("SELECT short_code FROM urls WHERE short_code = %s", (new_short_code,))
        if c.fetchone():
            conn.close()
            return {"success": False, "message": "Kode shortlink sudah digunakan!"}, 400
    c.execute("UPDATE urls SET short_code = %s, long_url = %s WHERE short_code = %s AND user_id = %s",
              (new_short_code, new_long_url, old_short_code, session['user_id']))
    if c.rowcount == 0:
        conn.close()
        return {"success": False, "message": "Shortlink tidak ditemukan atau akses ditolak!"}, 404
    conn.commit()
    conn.close()
    return {"success": True, "message": "Shortlink berhasil diperbarui!"}

@app.route('/analytics/<short_code>', methods=['GET'])
def analytics(short_code):
    if 'user_id' not in session:
        return {"success": False, "message": "Login diperlukan!"}, 401
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT click_count FROM urls WHERE short_code = %s AND user_id = %s", (short_code, session['user_id']))
    url_data = c.fetchone()
    if not url_data:
        conn.close()
        return {"success": False, "message": "Shortlink tidak ditemukan atau akses ditolak!"}, 404
    total_clicks = url_data[0]
    c.execute("SELECT click_date, click_count FROM clicks WHERE short_code = %s AND click_date >= CURRENT_DATE - INTERVAL '30 days' ORDER BY click_date ASC", (short_code,))
    click_data_raw = c.fetchall()
    click_data = [{"date": row[0].strftime('%Y-%m-%d'), "count": row[1]} for row in click_data_raw]
    conn.close()
    return {"success": True, "total_clicks": total_clicks, "qr_scans": 0, "last_click": "N/A", "click_data": click_data}

@app.route('/admin', methods=['GET'])
def admin():
    if not is_admin():
        flash('Akses ditolak! Hanya admin yang diperbolehkan.', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id, username, registered_at, last_ip, is_banned FROM users WHERE LOWER(username) != 'master'")
    users_raw = c.fetchall()
    users = [(user[0], user[1], user[2].strftime('%d %b %Y %H:%M:%S') if user[2] else 'N/A', user[3] or 'N/A', user[4]) for user in users_raw]
    user_shortlinks = {}
    for user in users:
        c.execute("SELECT short_code, long_url, click_count, created_at FROM urls WHERE user_id = %s ORDER BY created_at DESC", (user[0],))
        shortlinks = c.fetchall()
        user_shortlinks[user[0]] = [(s[0], s[1], s[2], s[3].strftime('%d %b %Y %H:%M:%S') if s[3] else 'N/A') for s in shortlinks]
    conn.close()
    return render_template('admin.html', users=users, user_shortlinks=user_shortlinks)

@app.route('/admin/ban_user/<int:user_id>/<action>')
def ban_user(user_id, action):
    if not is_admin():
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('dashboard'))
    if action not in ['ban', 'unban']:
        flash('Aksi tidak valid!', 'danger')
        return redirect(url_for('admin'))
    is_banned = action == 'ban'
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("UPDATE users SET is_banned = %s WHERE id = %s AND LOWER(username) != 'master'", (is_banned, user_id))
    conn.commit()
    flash(f'Pengguna berhasil {"dibanned" if is_banned else "di-unbanned"}!' if c.rowcount else 'Pengguna tidak ditemukan!', 'success' if c.rowcount else 'danger')
    conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/delete_user/<int:user_id>')
def delete_user(user_id):
    if not is_admin():
        flash('Akses ditolak!', 'danger')
        return redirect(url_for('dashboard'))
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("DELETE FROM urls WHERE user_id = %s", (user_id,))
    c.execute("DELETE FROM users WHERE id = %s AND LOWER(username) != 'master'", (user_id,))
    conn.commit()
    flash('Pengguna dan shortlinknya berhasil dihapus!' if c.rowcount else 'Pengguna tidak ditemukan!', 'success' if c.rowcount else 'danger')
    conn.close()
    return redirect(url_for('admin'))

@app.route('/admin/edit_user', methods=['POST'])
def edit_user():
    if not is_admin():
        return {"success": False, "message": "Akses ditolak!"}, 403
    data = request.get_json()
    user_id = data.get('user_id')
    new_username = data.get('username')
    new_password = data.get('password')
    if not user_id or not new_username:
        return {"success": False, "message": "Data tidak lengkap!"}, 400
    conn = get_db_connection()
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = %s AND id != %s", (new_username, user_id))
    if c.fetchone():
        conn.close()
        return {"success": False, "message": "Username sudah digunakan!"}, 400
    if new_password:
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        c.execute("UPDATE users SET username = %s, password = %s WHERE id = %s", (new_username, hashed_password, user_id))
    else:
        c.execute("UPDATE users SET username = %s WHERE id = %s", (new_username, user_id))
    conn.commit()
    conn.close()
    return {"success": True, "message": "Pengguna berhasil diperbarui!"}

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/privacy_policy')
def privacy_policy():
    return render_template('privacy_policy.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/shorten_redirect', methods=['POST'])
def shorten_url_redirect():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    long_url = request.form['url']
    short_code = request.form.get('short_code', '').strip()
    
    # Validasi URL panjang
    parsed_url = urlparse(long_url)
    if not parsed_url.scheme or not parsed_url.netloc:
        flash('URL tidak valid. Pastikan URL dimulai dengan http:// atau https://', 'danger')
        return redirect(url_for('dashboard'))
    
    # Validasi short_code jika diisi
    if short_code:
        # Periksa apakah short_code hanya mengandung huruf dan angka
        if not re.match(r'^[a-zA-Z0-9]+$', short_code):
            flash('Kode shortlink hanya boleh mengandung huruf dan angka.', 'danger')
            return redirect(url_for('dashboard'))
        
        # Periksa panjang short_code (3-10 karakter)
        if len(short_code) < 3 or len(short_code) > 10:
            flash('Kode shortlink harus memiliki panjang 3-10 karakter.', 'danger')
            return redirect(url_for('dashboard'))
    else:
        # Jika short_code kosong, buat kode acak
        short_code = ''.join(random.choices(string.ascii_letters + string.digits, k=6))
    
    # Periksa apakah short_code sudah ada di database
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT short_code FROM urls WHERE short_code = %s', (short_code,))
    existing_url = cur.fetchone()
    
    if existing_url:
        cur.close()
        conn.close()
        flash('Kode shortlink sudah digunakan. Silakan gunakan kode lain.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Simpan shortlink ke database
    user_id = session['user_id']
    cur.execute(
        'INSERT INTO urls (short_code, long_url, user_id, click_count) VALUES (%s, %s, %s, %s)',
        (short_code, long_url, user_id, 0)
    )
    conn.commit()
    cur.close()
    conn.close()
    
    flash(f'Shortlink berhasil dibuat: {request.host_url}{short_code}', 'success')
    return redirect(url_for('dashboard'))

@app.route('/forgot_password', methods=['GET', 'POST'])
@limiter.limit("5 per hour")
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("SELECT id, username FROM users WHERE email = %s", (email,))
        user = c.fetchone()
        if not user:
            conn.close()
            flash('Email tidak ditemukan!', 'danger')
            return redirect(url_for('forgot_password'))
        user_id = user[0]
        new_password = ''.join(random.choices(string.ascii_letters + string.digits, k=12))
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        c.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, user_id))
        conn.commit()
        if send_email(email, new_password):
            flash('Password baru telah dikirim ke email Anda!', 'success')
        else:
            flash('Gagal mengirim email, coba lagi nanti!', 'danger')
        conn.close()
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/sitemap.xml')
def sitemap():
    return send_from_directory('static', 'sitemap.xml')

@app.route('/robots.txt')
def robots_txt():
    return send_from_directory('static', 'robots.txt')

@app.route('/favicon.ico')
def favicon():
    return send_from_directory('static', 'favicon.ico')

@app.route('/static/favicon.ico')
def static_favicon():
    return send_from_directory('static', 'favicon.ico')

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)