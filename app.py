import os
import jwt
import datetime
import uuid
import csv
import io
import base64
import qrcode
from functools import wraps
from flask import Flask, request, jsonify, redirect, render_template_string, make_response
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo import MongoClient
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'super-secret-production-key')

# --- RATE LIMITING ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "100 per hour"],
    storage_uri="memory://"
)

# --- MONGODB CONFIGURATION ---
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['url_shortener']
users_collection = db['users']
urls_collection = db['urls']
clicks_collection = db['clicks'] # New collection for detailed analytics

# Create a TTL index for link expiration. (Documents expire automatically when 'expires_at' is reached)
urls_collection.create_index("expires_at", expireAfterSeconds=0)

# --- MIDDLEWARE ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(" ")[1]

        if not token:
            return jsonify({'error': 'Authentication token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'username': data['username']})
            if not current_user:
                raise Exception("User not found")
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired! Please log in again.'}), 401
        except Exception:
            return jsonify({'error': 'Invalid authentication token!'}), 401

        return f(current_user, *args, **kwargs)
    return decorated

# --- ROUTES ---
@app.route('/api/auth/register', methods=['POST'])
@limiter.limit("5 per minute")
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400

    if users_collection.find_one({'username': username}):
        return jsonify({'error': 'Username already exists'}), 409

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({
        'username': username,
        'password': hashed_password,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    })
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
@limiter.limit("10 per minute")
def login():
    data = request.get_json()
    user = users_collection.find_one({'username': data.get('username')})
    
    if not user or not check_password_hash(user['password'], data.get('password')):
        return jsonify({'error': 'Invalid credentials'}), 401

    token = jwt.encode({
        'username': user['username'],
        'exp': datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")

    return jsonify({'token': token, 'expires_in': '24h'}), 200

@app.route('/api/urls/shorten', methods=['POST'])
@token_required
@limiter.limit("20 per minute")
def shorten_url(current_user):
    data = request.get_json()
    original_url = data.get('url')
    password = data.get('password') # Optional link password
    expires_in_hours = data.get('expires_in_hours') # Optional TTL

    if not original_url:
        return jsonify({'error': 'Original URL is required'}), 400

    short_id = str(uuid.uuid4())[:8]
    short_url = f"{request.host_url}{short_id}"
    
    # 1. Generate QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=2)
    qr.add_data(short_url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    
    img_bytes = io.BytesIO()
    img.save(img_bytes, format='PNG')
    qr_base64 = base64.b64encode(img_bytes.getvalue()).decode('utf-8')

    # 2. Build Document
    new_url = {
        'short_id': short_id,
        'original_url': original_url,
        'created_by': current_user['username'],
        'clicks': 0,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }

    # Add optional features if requested
    if password:
        new_url['password_hash'] = generate_password_hash(password)
    
    if expires_in_hours:
        new_url['expires_at'] = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=float(expires_in_hours))

    urls_collection.insert_one(new_url)

    return jsonify({
        'message': 'URL shortened successfully',
        'short_url': short_url,
        'short_id': short_id,
        'qr_code': f"data:image/png;base64,{qr_base64}",
        'expires_at': new_url.get('expires_at')
    }), 201

@app.route('/api/urls/export/<short_id>', methods=['GET'])
@token_required
def export_analytics(current_user, short_id):
    # Verify ownership
    url_data = urls_collection.find_one({'short_id': short_id, 'created_by': current_user['username']})
    if not url_data:
        return jsonify({'error': 'URL not found or unauthorized'}), 404
        
    clicks = clicks_collection.find({'short_id': short_id}).sort("timestamp", -1)
    
    # Generate CSV in memory
    si = io.StringIO()
    cw = csv.writer(si)
    cw.writerow(['Timestamp', 'Browser', 'OS', 'Referrer'])
    
    for c in clicks:
        cw.writerow([c.get('timestamp'), c.get('browser'), c.get('os'), c.get('referrer')])
        
    output = make_response(si.getvalue())
    output.headers["Content-Disposition"] = f"attachment; filename={short_id}_analytics.csv"
    output.headers["Content-type"] = "text/csv"
    return output

@app.route('/api/urls/my-urls', methods=['GET'])
@token_required
def get_user_urls(current_user):
    user_urls = list(urls_collection.find(
        {'created_by': current_user['username']},
        {'_id': 0, 'password_hash': 0} 
    ))
    return jsonify({'count': len(user_urls), 'urls': user_urls}), 200

@app.route('/<short_id>', methods=['GET', 'POST'])
def redirect_url(short_id):
    url_data = urls_collection.find_one({'short_id': short_id})
    
    if not url_data:
        return jsonify({'error': 'URL not found or has expired'}), 404

    # Handle Password Protection
    if 'password_hash' in url_data:
        if request.method == 'GET':
            # Serve a basic HTML form to enter the password
            return render_template_string('''
                <div style="font-family: sans-serif; max-width: 400px; margin: 50px auto; padding: 20px; border: 1px solid #ccc; border-radius: 8px;">
                    <h2>Protected Link</h2>
                    <form method="POST">
                        <input type="password" name="password" placeholder="Enter password" required style="width: 100%; padding: 10px; margin-bottom: 10px;">
                        <button type="submit" style="width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer;">Access Link</button>
                    </form>
                </div>
            ''')
        
        if request.method == 'POST':
            provided_password = request.form.get('password')
            if not check_password_hash(url_data['password_hash'], provided_password):
                return "Invalid password", 403

    # Detailed Analytics Tracking
    user_agent = request.user_agent
    clicks_collection.insert_one({
        'short_id': short_id,
        'timestamp': datetime.datetime.now(datetime.timezone.utc),
        'browser': user_agent.browser,
        'os': user_agent.platform,
        'referrer': request.referrer or 'Direct'
    })

    # Increment global counter
    urls_collection.update_one({'short_id': short_id}, {'$inc': {'clicks': 1}})
        
    return redirect(url_data['original_url'])

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)