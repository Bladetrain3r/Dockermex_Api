# CoreApi.py
"""
CoreApi.py

This module provides a CoreApi class for managing the core API functionality 
using Flask. It includes methods for initializing the Flask application, 
configuring CORS, setting up basic and session configurations, and loading 
users on startup.

Classes:
    CoreApi: Manages the Flask application and its configurations.

Usage:
    core_api = CoreApi()
    core_api.app.run()

Dependencies:
    - flask
    - flask_cors
    - json
    - os
    - hashlib
    - functools
    - ApiUtils (rate_limit, validate_file_type, log_access, require_json)
    - typing
    - secrets
"""
# ApiCore.py
import hashlib
import os
import secrets
from functools import wraps
import json
from ApiDatabase import DatabaseManager
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from ApiUtils import rate_limit, validate_file_type, log_access, require_json

class CoreApi:
    def __init__(self):
        self.app = Flask(__name__)
        self.db = DatabaseManager()
        
        CORS(self.app, 
             supports_credentials=True,  # Keep this for cookies
             resources={
                 r"/*": {
                     "origins": ["http://odamex.zerofuchs.co.za:443", "https://odamex.zerofuchs.co.za:443"],
                     "methods": ["GET", "POST", "OPTIONS"],
                     "allow_headers": ["Content-Type", "Authorization"],
                     "expose_headers": ["Content-Range", "X-Content-Range"],
                     "supports_credentials": True
                 }
             })
        
        # Basic configuration
        self.app.config['UPLOAD_FOLDER'] = '/pwads'
        self.app.config['IWAD_FOLDER'] = '/iwads/freeware'
        self.app.config['COMMERCIAL_IWAD_FOLDER'] = '/iwads/commercial'
        self.app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 2048
        self.app.config['SERVICE_CONFIG_FOLDER'] = '/service-configs'
        self.app.config['CONFIG_FOLDER'] = '/configs'
        
        # Session configuration - still needed for cookie handling
        self.app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
        
        self._register_routes()

    def require_auth(self, f):
        """Authentication requirement decorator"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            token = request.cookies.get('session_token')
            if not token:
                return jsonify({'error': 'Authentication required'}), 401
            
            user = self.db.verify_session(token)
            if not user:
                response = make_response(jsonify({'error': 'Invalid session'}), 401)
                response.delete_cookie('session_token')
                return response
                
            return f(*args, **kwargs)
        return decorated_function
    
    def require_role(self, role):
        """Role requirement decorator"""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = request.cookies.get('session_token')
                if not token:
                    return jsonify({'error': 'Authentication required'}), 401
                
                user = self.db.verify_session(token)
                if not user:
                    response = make_response(jsonify({'error': 'Invalid session'}), 401)
                    response.delete_cookie('session_token')
                    return response
                
                if user['role'] != role:
                    return jsonify({'error': 'Insufficient permissions'}), 403
                
                return f(*args, **kwargs)
            return decorated_function
        return decorator

    def _register_routes(self):
        """Register all API routes"""
        
        @self.app.route('/auth/login', methods=['POST'])
        @rate_limit(requests_per_window=5, window_seconds=60)
        @require_json()
        @log_access()
        def login():
            data = request.get_json()
            username = data.get('username')
            password = data.get('password')
            
            user = self.db.verify_user(username, password)
            if user:
                token = self.db.create_session(user['id'])
                if not token:
                    return jsonify({"error": "Could not create session"}), 500
                    
                response = jsonify({
                    "message": "Login successful",
                    "user": {
                        "username": user['username'],
                        "role": user['role']
                    }
                })
                
                # Set secure cookie with token
                response.set_cookie(
                    'session_token',
                    token,
                    httponly=True,
                    secure=True,
                    samesite='Strict',
                    max_age=3600  # 1 hour
                )
                
                return response, 200
            return jsonify({"error": "Invalid credentials"}), 401

        @self.app.route('/auth/logout', methods=['POST'])
        def logout():
            token = request.cookies.get('session_token')
            if token:
                self.db.invalidate_session(token)
            
            response = jsonify({"message": "Logout successful"})
            response.delete_cookie('session_token')
            return response

        @self.app.route('/auth/session', methods=['GET'])
        def check_session():
            token = request.cookies.get('session_token')
            if not token:
                return jsonify({"authenticated": False}), 401
                
            user = self.db.verify_session(token)
            if user:
                return jsonify({
                    "authenticated": True,
                    "user": {
                        "username": user['username'],
                        "role": user['role']
                    }
                }), 200
                
            response = make_response(jsonify({"authenticated": False}), 401)
            response.delete_cookie('session_token')
            return response
        
        # Admin routes
        @self.app.route('/admin/users', methods=['GET'])
        @self.require_role('admin')
        def list_users():
            users = self.db.list_users()
            for user in users:
                user['storage_used'] = self.db.get_user_storage_usage(user['id'])
                user['storage_limit'] = self.db.STORAGE_LIMITS[user['role']]
            return jsonify(users)
        
        @self.app.route('/admin/wads', methods=['GET'])
        @self.require_role('admin')
        def list_wads():
            wads = self.db.get_all_wads() # Need to add this method
            return jsonify(wads)
        
        @self.app.route('/admin/configs', methods=['GET'])
        @self.require_role('admin')
        def list_configs():
            configs = self.db.get_active_configs()
            return jsonify(configs)

        # WAD management routes with auth requirement
        @self.app.route('/submit-wad', methods=['POST'])
        @self.require_auth
        @rate_limit(requests_per_window=10, window_seconds=60)
        @validate_file_type('.wad')
        @log_access()
        def upload_file():
            if 'file' not in request.files:
                return jsonify({'error': 'No file provided'}), 400
        
            token = request.cookies.get('session_token')
            user = self.db.verify_session(token)
            if not user:
                return jsonify({'error': 'Invalid session'}), 401
        
            file = request.files['file']
            filename = file.filename.strip()
            
            # Determine if this is an IWAD upload
            is_iwad = 'iwad' in request.form and request.form['iwad'].lower() == 'true'
            folder = self.app.config['IWAD_FOLDER'] if is_iwad else self.app.config['UPLOAD_FOLDER']
        
            # Get file size and hash
            file.seek(0, 2)  # Seek to end
            filesize = file.tell()  # Get position (size)
            file.seek(0)  # Reset to beginning
            
            # Check storage limits for non-admin users
            if user['role'] != 'admin':
                if not self.db.can_upload_file(user['id'], filesize):
                    return jsonify({'error': 'Storage limit exceeded'}), 403
        
            # Calculate hash
            file_content = file.read()
            file_hash = hashlib.sha256(file_content).hexdigest().lower()
            file.seek(0)  # Reset file pointer again
        
            # Check for commercial WAD conflicts
            if folder == self.app.config['UPLOAD_FOLDER']:
                commercial_check = self._check_commercial_wad(filename, file_hash)
                if commercial_check:
                    return commercial_check
        
            # Save the file
            upload_path = os.path.join(folder, filename)
            try:
                file.save(upload_path)
            except Exception as e:
                return jsonify({'error': f'Failed to save file: {str(e)}'}), 500
        
            # Register WAD in database
            wad_id = self.db.register_wad(
                filename=filename,
                hash=file_hash,
                upload_path=upload_path,
                wad_type='IWAD' if is_iwad else 'PWAD',
                uploader_id=user['id'],
                filesize=filesize,
                description=request.form.get('description', ''),
                is_commercial=False
            )
        
            if not wad_id:
                # If database registration fails, try to remove the file
                try:
                    os.remove(upload_path)
                except ValueError as e:
                    print("%s", e)  # Already in error state, ignore cleanup failure
                return jsonify({'error': 'Failed to register WAD in database'}), 500
        
            return jsonify({
                'message': 'File uploaded successfully',
                'filename': filename,
                'hash': file_hash,
                'wad_id': wad_id,
                'size': filesize
            }), 200

        # List routes

        @self.app.route('/list-configs', methods=['GET'])
        @self.require_auth
        @rate_limit(requests_per_window=30, window_seconds=60)
        @log_access()
        def list_configs():
            configs = [f for f in os.listdir(self.app.config['CONFIG_FOLDER']) 
                      if f.lower().endswith('.cfg')]
            return jsonify(configs)

        @self.app.route('/list-pwads', methods=['GET'])
        @self.require_auth
        @rate_limit(requests_per_window=30, window_seconds=60)
        @log_access()
        def list_pwads():
            wads = [f for f in os.listdir(self.app.config['UPLOAD_FOLDER']) 
                   if f.lower().endswith('.wad')]
            wads.insert(0, '')  # Add empty option
            return jsonify(wads)

        @self.app.route('/list-iwads', methods=['GET'])
        @self.require_auth
        @rate_limit(requests_per_window=30, window_seconds=60)
        @log_access()
        def list_iwads():
            wads = [
                f for f in os.listdir(self.app.config['IWAD_FOLDER'])
                if f.lower().endswith('.wad') and not f.lower().startswith('odamex')
            ]
            commercial_wads = [
                f for f in os.listdir(self.app.config['COMMERCIAL_IWAD_FOLDER'])
                if f.lower().endswith('.wad') and not f.lower().startswith('odamex')
            ]
            return jsonify(wads + commercial_wads)
        
        # Configuration routes
        
        @self.app.route('/generate-config', methods=['POST'])
        @self.require_auth
        @rate_limit(requests_per_window=20, window_seconds=60)
        @require_json()
        @log_access()
        def submit_config():
            config_data = request.json
            config_name = (
                f"{config_data.get('configFile').split('.')[0]}_"
                f"{config_data.get('iwadFile').split('.')[0]}_"
                f"{config_data.get('pwadFile').split('.')[0]}.json"
            )
            config_path = os.path.join(self.app.config['SERVICE_CONFIG_FOLDER'], config_name)
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, ensure_ascii=False, indent=4)
        
            configs = [f for f in os.listdir(self.app.config['CONFIG_FOLDER']) if f.lower().endswith('.cfg')]
            pwads = [f for f in os.listdir(self.app.config['UPLOAD_FOLDER']) if f.lower().endswith('.wad')]
            iwads = [f for f in os.listdir(self.app.config['IWAD_FOLDER']) if f.lower().endswith('.wad')]
        
            return jsonify({
                'message': 'Configuration saved',
                'configs': configs,
                'pwads': pwads,
                'iwads': iwads
            }), 200
        
        @self.app.route('/delete-config', methods=['POST'])
        @self.require_role('admin')
        @self.require_auth
        @rate_limit(requests_per_window=20, window_seconds=60)
        @require_json()
        @log_access()
        def delete_config():
            config_name = request.json.get('configFile')
            config_path = os.path.join(self.app.config['SERVICE_CONFIG_FOLDER'], config_name)
            if os.path.exists(config_path):
                os.remove(config_path)
        
            configs = [f for f in os.listdir(self.app.config['CONFIG_FOLDER']) if f.lower().endswith('.cfg')]
            pwads = [f for f in os.listdir(self.app.config['UPLOAD_FOLDER']) if f.lower().endswith('.wad')]
            iwads = [f for f in os.listdir(self.app.config['IWAD_FOLDER']) if f.lower().endswith('.wad')]
        
            return jsonify({
                'message': 'Configuration deleted',
                'configs': configs,
                'pwads': pwads,
                'iwads': iwads
            }), 200

    def _check_commercial_wad(self, filename: str, file_hash: str):
        """Check if a WAD file matches any known commercial WADs"""
        commercial_iwads = {}
        for f in os.listdir(self.app.config['COMMERCIAL_IWAD_FOLDER']):
            if f.lower().endswith('.wad'):
                wad_path = os.path.join(self.app.config['COMMERCIAL_IWAD_FOLDER'], f)
                with open(wad_path, 'rb') as wad_file:
                    wad_hash = hashlib.sha256(wad_file.read()).hexdigest().lower()
                    commercial_iwads[os.path.splitext(f)[0].lower()] = {
                        'filename': f,
                        'hash': wad_hash
                    }

        upload_full = filename.lower()
        upload_name = os.path.splitext(filename)[0].lower()

        if file_hash in [comm_data['hash'] for comm_data in commercial_iwads.values()]:
            return jsonify({'error': 'File matches a commercial IWAD'}), 400

        for comm_name, comm_data in commercial_iwads.items():
            if upload_full == comm_data['filename'].lower() or upload_name == comm_name:
                return jsonify({'error': f'File matches commercial IWAD: {comm_name}'}), 400

        return None

    def run(self, host='0.0.0.0', port=5000, **kwargs):
        """Run the API server"""
        self.app.run(host=host, port=port, **kwargs)

if __name__ == '__main__':
    api = CoreApi()
    api.run(debug=True)