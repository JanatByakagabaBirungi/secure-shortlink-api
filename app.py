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

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client['url_shortener']
users_collection = db['users']
urls_collection = db['urls']

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
def shorten_url(current_user):
    data = request.get_json()
    original_url = data.get('url')

    if not original_url:
        return jsonify({'error': 'Original URL is required'}), 400

    short_id = str(uuid.uuid4())[:8]
    
    new_url = {
        'short_id': short_id,
        'original_url': original_url,
        'created_by': current_user['username'],
        'clicks': 0,
        'created_at': datetime.datetime.now(datetime.timezone.utc)
    }
    urls_collection.insert_one(new_url)

    return jsonify({
        'message': 'URL shortened successfully',
        'short_url': f"{request.host_url}{short_id}",
        'short_id': short_id,
    }), 201

@app.route('/api/urls/my-urls', methods=['GET'])
@token_required
def get_user_urls(current_user):
    # Analytics endpoint to view all URLs created by the user and their click counts
    user_urls = list(urls_collection.find(
        {'created_by': current_user['username']},
        {'_id': 0, 'password': 0} 
    ))
    return jsonify({'count': len(user_urls), 'urls': user_urls}), 200

@app.route('/<short_id>', methods=['GET'])
def redirect_url(short_id):
    # Find the URL and increment the click counter in one atomic operation
    url_data = urls_collection.find_one_and_update(
        {'short_id': short_id},
        {'$inc': {'clicks': 1}}
    )
    
    if not url_data:
        return jsonify({'error': 'URL not found'}), 404
        
    return redirect(url_data['original_url'])

if __name__ == '__main__':
    # Bind to 0.0.0.0 for Docker compatibility
    app.run(host='0.0.0.0', port=5000, debug=True)