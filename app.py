#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Main Application
This module serves as the entry point for the Syslog management system.
It initializes the Flask web server and the Syslog server.
"""

import os
import json
import threading
import logging
import ssl
import socket
import psutil
import signal
import atexit
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, send_from_directory
from flask_login import LoginManager, login_required, login_user, logout_user, current_user
from flask_wtf.csrf import CSRFProtect
from flask_wtf import FlaskForm
from wtforms import FileField, SubmitField, StringField, BooleanField, IntegerField, SelectField
from wtforms.validators import DataRequired, Optional, NumberRange, URL, ValidationError
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from config import Config
from auth import User, init_users, save_users, HASH_METHOD

# Import from modular syslog handler components
from source_manager import start_syslog_server
from core_handler import get_source_stats, get_system_metrics, flush_all_metadata
from log_processor import parse_logs_for_timerange
from syslog_server import check_port_availability
from monitoring import start_monitoring_service, update_monitoring_config, get_monitoring_status
from utils import check_system_resources

# Import the Windows Event monitor to check availability
try:
    from windows_event_monitor import get_available_event_logs, is_windows, EVTX_AVAILABLE
    WINDOWS_EVENT_AVAILABLE = is_windows() and EVTX_AVAILABLE
except ImportError:
    WINDOWS_EVENT_AVAILABLE = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("syslog_manager.log"),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

# Initialize Flask application
app = Flask(__name__)
app.config.from_object(Config)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Add datetime function to templates
@app.context_processor
def inject_now():
    return {'now': datetime.now}

# Initialize login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Initialize users
users = init_users()

# Certificate upload form
class CertificateForm(FlaskForm):
    cert_file = FileField('Certificate File (PEM)', validators=[DataRequired()])
    key_file = FileField('Private Key File (PEM)', validators=[DataRequired()])
    submit = SubmitField('Upload')

# Monitoring settings form
class MonitoringForm(FlaskForm):
    enabled = BooleanField('Enable Application Monitoring')
    hec_url = StringField('HEC URL', validators=[Optional(), URL()])
    hec_token = StringField('HEC Token', validators=[Optional()])
    interval = IntegerField('Monitoring Interval (seconds)', 
                           validators=[NumberRange(min=10, max=3600)],
                           default=60)
    # New fields for monitoring configuration
    monitor_system = BooleanField('Monitor System Metrics (CPU, Memory, Disk)', default=True)
    monitor_events = BooleanField('Monitor Event Statistics', default=True)
    monitor_sources = BooleanField('Monitor Sources and Ports', default=True)
    monitor_threads = BooleanField('Monitor Thread Information', default=False)
    monitor_alerts = BooleanField('Include Alerts', default=True)
    custom_field_name = StringField('Custom Field Name')
    custom_field_value = StringField('Custom Field Value')
    submit = SubmitField('Save Settings')

# Load source configurations
def load_sources():
    if os.path.exists(os.path.join(Config.DATA_DIR, 'sources.json')):
        try:
            with open(os.path.join(Config.DATA_DIR, 'sources.json'), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading sources: {str(e)}")
            return {}
    return {}

def save_sources(sources):
    try:
        with open(os.path.join(Config.DATA_DIR, 'sources.json'), 'w', encoding='utf-8') as f:
            json.dump(sources, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving sources: {str(e)}")

# Load monitoring configuration
def load_monitoring_config():
    if os.path.exists(os.path.join(Config.DATA_DIR, 'monitoring.json')):
        try:
            with open(os.path.join(Config.DATA_DIR, 'monitoring.json'), 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error loading monitoring config: {str(e)}")
            return {
                "enabled": False,
                "hec_url": "",
                "hec_token": "",
                "interval": 60,
                "monitor_system": True,
                "monitor_events": True,
                "monitor_sources": True,
                "monitor_threads": False,
                "monitor_alerts": True,
                "custom_fields": {}
            }
    return {
        "enabled": False,
        "hec_url": "",
        "hec_token": "",
        "interval": 60,
        "monitor_system": True,
        "monitor_events": True,
        "monitor_sources": True,
        "monitor_threads": False,
        "monitor_alerts": True,
        "custom_fields": {}
    }

sources = load_sources()
monitoring_config = load_monitoring_config()

@login_manager.user_loader
def load_user(user_id):
    return users.get(user_id)

@app.route('/')
@login_required
def index():
    """Render the main dashboard."""
    # Get updated stats for each source
    source_stats = get_source_stats(sources)
    system_metrics = get_system_metrics()
    
    # If this is the first login with default credentials, redirect to change password
    if current_user.id == 'admin' and current_user.must_change_password:
        flash('You must change your password before proceeding.', 'warning')
        return redirect(url_for('change_password'))
        
    return render_template('dashboard.html', sources=source_stats, metrics=system_metrics, 
                          windows_event_available=WINDOWS_EVENT_AVAILABLE)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle user login."""
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = users.get(username)
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
            
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    """Handle user logout."""
    logout_user()
    return redirect(url_for('login'))

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Handle password change."""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        if not check_password_hash(current_user.password_hash, current_password):
            flash('Current password is incorrect', 'danger')
        elif new_password != confirm_password:
            flash('New passwords do not match', 'danger')
        elif len(new_password) < 8:
            flash('Password must be at least 8 characters long', 'danger')
        else:
            # Update password with compatible hash method
            current_user.password_hash = generate_password_hash(new_password, method=HASH_METHOD)
            current_user.must_change_password = False
            save_users(users)
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
            
    return render_template('change_password.html')

@app.route('/certificates', methods=['GET', 'POST'])
@login_required
def certificates():
    """Handle SSL certificate management."""
    form = CertificateForm()
    cert_status = {
        'has_cert': os.path.exists(Config.SSL_CERT_FILE),
        'has_key': os.path.exists(Config.SSL_KEY_FILE),
        'is_valid': False
    }
    
    # Check if certificate and key are valid
    if cert_status['has_cert'] and cert_status['has_key']:
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(
                Config.SSL_CERT_FILE,
                Config.SSL_KEY_FILE
            )
            cert_status['is_valid'] = True
        except Exception as e:
            logger.error(f"Error validating certificate: {str(e)}")
    
    if form.validate_on_submit():
        # Save certificate file
        cert_file = form.cert_file.data
        cert_path = Config.SSL_CERT_FILE
        cert_file.save(cert_path)
        
        # Save private key file
        key_file = form.key_file.data
        key_path = Config.SSL_KEY_FILE
        key_file.save(key_path)
        
        # Verify the certificate and key
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            flash('SSL certificate and private key uploaded successfully. Restart the server to apply changes.', 'success')
            return redirect(url_for('certificates'))
        except Exception as e:
            os.remove(cert_path)
            os.remove(key_path)
            flash(f'Invalid certificate or private key: {str(e)}', 'danger')
    
    return render_template('certificates.html', form=form, cert_status=cert_status)

@app.route('/monitoring', methods=['GET', 'POST'])
@login_required
def monitoring():
    """Handle monitoring configuration."""
    global monitoring_config
    
    # Get current monitoring status
    monitoring_status = get_monitoring_status()
    
    # Add timestamp if active
    if monitoring_status['active']:
        # Find monitoring.json modification time
        monitoring_file = os.path.join(Config.DATA_DIR, 'monitoring.json')
        if os.path.exists(monitoring_file):
            mod_time = datetime.fromtimestamp(os.path.getmtime(monitoring_file))
            monitoring_status['started_at'] = mod_time.strftime('%Y-%m-%d %H:%M:%S')
    
    # Initialize form with current values
    form = MonitoringForm(obj=monitoring_status['config'])
    
    if form.validate_on_submit():
        # Create basic monitoring configuration
        monitoring_config = {
            "enabled": form.enabled.data,
            "hec_url": form.hec_url.data,
            "hec_token": form.hec_token.data,
            "interval": form.interval.data,
            "monitor_system": form.monitor_system.data,
            "monitor_events": form.monitor_events.data,
            "monitor_sources": form.monitor_sources.data,
            "monitor_threads": form.monitor_threads.data,
            "monitor_alerts": form.monitor_alerts.data,
        }
        
        # Process custom fields
        custom_fields = {}
        
        # Handle existing custom fields
        if 'custom_fields' in monitoring_status['config']:
            custom_fields = monitoring_status['config']['custom_fields'].copy()
        
        # Process custom fields from form
        custom_field_updates = request.form.getlist('custom_fields[]')
        if custom_field_updates:
            for i in range(0, len(custom_field_updates), 2):
                if i + 1 < len(custom_field_updates):
                    name = custom_field_updates[i]
                    value = custom_field_updates[i + 1]
                    if name and value:
                        custom_fields[name] = value
        
        # Handle individual custom fields with array notation
        for key, value in request.form.items():
            if key.startswith('custom_fields[') and key.endswith(']'):
                name = key[14:-1]  # Extract name from custom_fields[name]
                if name:
                    custom_fields[name] = value
        
        # Add new custom field if provided
        if form.custom_field_name.data and form.custom_field_value.data:
            custom_fields[form.custom_field_name.data] = form.custom_field_value.data
        
        # Handle field removal
        remove_field = request.form.get('remove_custom_field')
        if remove_field and remove_field in custom_fields:
            del custom_fields[remove_field]
        
        # Add custom fields to config
        monitoring_config['custom_fields'] = custom_fields
        
        # Save configuration
        try:
            with open(os.path.join(Config.DATA_DIR, 'monitoring.json'), 'w', encoding='utf-8') as f:
                json.dump(monitoring_config, f, indent=4)
        except Exception as e:
            logger.error(f"Error saving monitoring config: {str(e)}")
            flash(f'Error saving monitoring settings: {str(e)}', 'danger')
            return redirect(url_for('monitoring'))
        
        # Update monitoring service
        update_monitoring_config(monitoring_config)
        
        flash('Monitoring settings updated successfully', 'success')
        return redirect(url_for('monitoring'))
    
    # Add resource requirements info for EPS levels
    resource_check = check_system_resources(Config.TARGET_EPS)
    
    return render_template('monitoring.html', form=form, resource_check=resource_check, 
                           monitoring_status=monitoring_status)

# Exempt CSRF for API sources endpoint
@csrf.exempt
@app.route('/api/sources', methods=['GET', 'POST'])
@login_required
def api_sources():
    """API endpoint for source management."""
    global sources
    
    if request.method == 'POST':
        try:
            source_data = request.json
            if not source_data:
                logger.error("Invalid JSON data received")
                return jsonify({'status': 'error', 'message': 'Invalid JSON data received'}), 400
                
            source_id = source_data.get('id')
            
            # Log received data for debugging
            logger.info(f"Received source data: {source_data}")
            
            # Validate source data
            if not source_data.get('name'):
                return jsonify({'status': 'error', 'message': 'Source name is required'}), 400
                
            # Check source type and required fields
            source_type = source_data.get('source_type')
            if source_type not in ['syslog', 'folder', 'file', 'windows_event']:
                return jsonify({'status': 'error', 'message': 'Invalid source type'}), 400
            
            # Validate target type and required fields
            target_type = source_data.get('target_type')
            if target_type not in ['file', 'hec']:
                return jsonify({'status': 'error', 'message': 'Invalid target type'}), 400
            
            # Validate source configuration based on type
            if source_type == 'syslog':
                if not source_data.get('source_ip'):
                    return jsonify({'status': 'error', 'message': 'Source IP is required for syslog source'}), 400
                
                # Get the port value and ensure it's an integer
                try:
                    port = int(source_data.get('port', 514))
                    source_data['port'] = port  # Ensure it's stored as an integer
                except ValueError:
                    return jsonify({'status': 'error', 'message': 'Port must be a valid number'}), 400
                
                if port < 1 or port > 65535:
                    return jsonify({'status': 'error', 'message': 'Port must be between 1 and 65535'}), 400

                # Platform-independent privileged port check
                if port < 1024:
                    import platform
                    if platform.system() == "Windows":
                        import ctypes
                        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                        if not is_admin:
                            logger.warning(f"Port {port} is a privileged port - may require elevated privileges on Windows")
                    else:
                        # Unix-like systems
                        try:
                            is_root = os.geteuid() == 0
                            if not is_root:
                                logger.warning(f"Port {port} is a privileged port - may require elevated privileges")
                        except AttributeError:
                            # In case os.geteuid() is not available
                            logger.warning(f"Port {port} is a privileged port - may require elevated privileges")

                # Import the port availability check function
                from syslog_server import check_port_availability
                
                # Check if port is available - only for new sources or changed ports
                if not source_id or (source_id in sources and int(sources[source_id].get('port', 514)) != port):
                    logger.info(f"Checking availability of port {port}")
                    if not check_port_availability(port):
                        # Try with system resources too - potentially more reliable port check
                        from syslog_handler import check_port_availability as handler_check_port
                        if not handler_check_port(port):
                            return jsonify({'status': 'error', 
                                            'message': f'Port {port} is not available. It may be in use by another process or requires elevated privileges.'}), 400
                                            
            elif source_type == 'folder':
                if not source_data.get('folder_path'):
                    return jsonify({'status': 'error', 'message': 'Folder path is required for folder source'}), 400
                
                folder_path = source_data.get('folder_path')
                if not os.path.isdir(folder_path):
                    return jsonify({'status': 'error', 'message': 'Folder path does not exist or is not accessible'}), 400
                
            elif source_type == 'file':
                if not source_data.get('file_path'):
                    return jsonify({'status': 'error', 'message': 'File path is required for file source'}), 400
                
                file_path = source_data.get('file_path')
                if not os.path.isfile(file_path):
                    return jsonify({'status': 'error', 'message': 'File path does not exist or is not accessible'}), 400
                    
            elif source_type == 'windows_event':
                if not WINDOWS_EVENT_AVAILABLE:
                    return jsonify({'status': 'error', 'message': 'Windows Event monitoring is not available on this system'}), 400
                    
                if not source_data.get('event_log'):
                    return jsonify({'status': 'error', 'message': 'Event log is required for Windows Event source'}), 400
                                
            # Validate target configuration based on type
            if target_type == 'file':
                if not source_data.get('target_directory'):
                    return jsonify({'status': 'error', 'message': 'Target directory is required for file target'}), 400
                
                # Validate target directory access
                target_dir = source_data.get('target_directory')
                logger.info(f"Validating target directory: {target_dir}")
                
                if not os.path.exists(target_dir):
                    try:
                        logger.info(f"Creating target directory: {target_dir}")
                        os.makedirs(target_dir, exist_ok=True)
                        # Verify we can write to it
                        test_file = os.path.join(target_dir, '.test_write')
                        with open(test_file, 'w') as f:
                            f.write('test')
                        os.remove(test_file)
                        logger.info(f"Successfully created and verified write access to: {target_dir}")
                    except PermissionError as e:
                        logger.error(f"Permission error accessing target directory {target_dir}: {str(e)}")
                        return jsonify({'status': 'error', 'message': f'Permission denied to target directory: {str(e)}'}), 400
                    except Exception as e:
                        logger.error(f"Error accessing target directory {target_dir}: {str(e)}")
                        return jsonify({'status': 'error', 'message': f'Cannot access target directory: {str(e)}'}), 400
            
            elif target_type == 'hec':
                if not source_data.get('hec_url'):
                    return jsonify({'status': 'error', 'message': 'HEC URL is required for HEC target'}), 400
                
                if not source_data.get('hec_token'):
                    return jsonify({'status': 'error', 'message': 'HEC token is required for HEC target'}), 400
            
            # Update sources and save
            try:
                if source_id:
                    # Update existing source
                    logger.info(f"Updating existing source: {source_id}")
                    sources[source_id] = source_data
                else:
                    # Add new source with auto-generated ID
                    import uuid
                    new_id = str(uuid.uuid4())
                    source_data['id'] = new_id
                    logger.info(f"Creating new source with ID: {new_id}")
                    sources[new_id] = source_data
                    
                    # Create empty JSON file for this source
                    source_json_path = os.path.join(Config.DATA_DIR, f'{new_id}.json')
                    logger.info(f"Creating JSON file: {source_json_path}")
                    with open(source_json_path, 'w', encoding='utf-8') as f:
                        json.dump([], f)
                
                # Save sources configuration
                logger.info("Saving sources configuration")
                save_sources(sources)
                
                return jsonify({'status': 'success', 'sources': sources})
            except Exception as e:
                logger.error(f"Error saving source data: {str(e)}", exc_info=True)
                return jsonify({'status': 'error', 'message': f'Error saving source: {str(e)}'}), 500
                
        except Exception as e:
            logger.error(f"Unexpected error in API sources: {str(e)}", exc_info=True)
            return jsonify({'status': 'error', 'message': f'Unexpected error: {str(e)}'}), 500
    
    # GET request - return all sources with stats
    try:
        source_stats = get_source_stats(sources)
        system_metrics = get_system_metrics()
        return jsonify({
            'status': 'success', 
            'sources': source_stats,
            'metrics': system_metrics
        })
    except Exception as e:
        logger.error(f"Error getting source stats: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error retrieving sources: {str(e)}'}), 500

# Exempt CSRF for API endpoints
@csrf.exempt
@app.route('/api/sources/<source_id>', methods=['GET', 'DELETE'])
@login_required
def api_source(source_id):
    """API endpoint for individual source operations."""
    global sources
    
    if source_id not in sources:
        return jsonify({'status': 'error', 'message': 'Source not found'}), 404
    
    if request.method == 'DELETE':
        del sources[source_id]
        save_sources(sources)
        return jsonify({'status': 'success'})
    
    # GET request - return specific source with stats
    source_data = sources[source_id]
    stats = get_source_stats({source_id: source_data})
    return jsonify({'status': 'success', 'source': stats.get(source_id, {})})

# Endpoint for live source statistics
@app.route('/api/source_stats/<source_id>', methods=['GET'])
@login_required
def api_source_stats(source_id):
    """API endpoint for getting live source statistics."""
    if source_id not in sources:
        return jsonify({'status': 'error', 'message': 'Source not found'}), 404
    
    try:
        stats = get_source_stats({source_id: sources[source_id]})
        return jsonify({
            'status': 'success', 
            'log_count': stats[source_id]['log_count'],
            'last_log_time': stats[source_id]['last_log_time']
        })
    except Exception as e:
        logger.error(f"Error getting source stats: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error retrieving source stats: {str(e)}'}), 500

# Endpoint for system metrics
@app.route('/api/system_metrics', methods=['GET'])
@login_required
def api_system_metrics():
    """API endpoint for getting system metrics."""
    try:
        metrics = get_system_metrics()
        return jsonify({'status': 'success', 'metrics': metrics})
    except Exception as e:
        logger.error(f"Error getting system metrics: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error retrieving system metrics: {str(e)}'}), 500

# Exempt CSRF for API endpoints
@csrf.exempt
@app.route('/api/investigate/<source_id>', methods=['POST'])
@login_required
def api_investigate(source_id):
    """API endpoint for log investigation."""
    if source_id not in sources:
        return jsonify({'status': 'error', 'message': 'Source not found'}), 404
    
    timerange = request.json
    start_time = timerange.get('start')
    end_time = timerange.get('end')
    
    if not start_time or not end_time:
        return jsonify({'status': 'error', 'message': 'Invalid time range'}), 400
    
    try:
        log_data = parse_logs_for_timerange(source_id, start_time, end_time)
        return jsonify({'status': 'success', 'data': log_data})
    except Exception as e:
        logger.error(f"Error processing logs: {str(e)}", exc_info=True)
        return jsonify({'status': 'error', 'message': f'Error processing logs: {str(e)}'}), 500

# Add API endpoint for monitoring status
@app.route('/api/monitoring/status', methods=['GET'])
@login_required
def api_monitoring_status():
    """API endpoint for getting monitoring status."""
    try:
        status = get_monitoring_status()
        
        # Add last sent timestamp if available
        last_sent = status.get('last_sent_time')
        if last_sent:
            formatted_time = datetime.fromtimestamp(last_sent).strftime('%Y-%m-%d %H:%M:%S')
        else:
            formatted_time = None
        
        return jsonify({
            'status': 'success',
            'monitoring_active': status['active'],
            'thread_running': status['thread_running'],
            'last_sent': formatted_time
        })
    except Exception as e:
        logger.error(f"Error getting monitoring status: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error retrieving monitoring status: {str(e)}'
        }), 500

# Add a new endpoint for getting Windows Event log information
@app.route('/api/windows_event_logs', methods=['GET'])
@login_required
def api_windows_event_logs():
    """API endpoint for getting Windows Event log information."""
    try:
        if not WINDOWS_EVENT_AVAILABLE:
            return jsonify({
                'status': 'error',
                'message': 'Windows Event monitoring is not available on this system',
                'available': False
            }), 400
        
        available_logs = get_available_event_logs()
        
        return jsonify({
            'status': 'success',
            'available': True,
            'logs': available_logs,
            'severity_levels': ['Verbose', 'Information', 'Warning', 'Error', 'Critical']
        })
    except Exception as e:
        logger.error(f"Error getting Windows Event logs: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': f'Error getting Windows Event logs: {str(e)}',
            'available': False
        }), 500

def get_ssl_context():
    """Get SSL context for HTTPS if certificate and key exist."""
    cert_path = os.path.join('certs', 'certificate.pem')
    key_path = os.path.join('certs', 'private_key.pem')
    
    if os.path.exists(cert_path) and os.path.exists(key_path):
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(cert_path, key_path)
            return context
        except Exception as e:
            logger.error(f"Error loading SSL certificate: {str(e)}")
    
    return None

def start_web_server():
    """Start the web server based on environment and SSL configuration."""
    flask_env = os.environ.get('FLASK_ENV', 'production').lower()
    ssl_context = get_ssl_context()
    
    if flask_env == 'development':
        logger.info(f"Starting Flask development server on {Config.FLASK_HOST}:{Config.FLASK_PORT}")
        app.run(
            host=Config.FLASK_HOST,
            port=Config.FLASK_PORT,
            debug=Config.DEBUG,
            ssl_context=ssl_context
        )
    else:
        # Production mode - use Waitress with SSL if available
        from waitress import serve
        threads = int(os.environ.get('WAITRESS_THREADS', psutil.cpu_count() * 2))
        
        if ssl_context:
            # For SSL with Waitress, we need to use a TLS-enabled server adapter
            import ssl
            from waitress.server import create_server
            
            server = create_server(
                app,
                host=Config.FLASK_HOST,
                port=Config.FLASK_PORT,
                threads=threads,
                url_scheme='https'
            )
            
            # Wrap the socket with SSL
            server.socket = ssl_context.wrap_socket(
                server.socket,
                server_side=True
            )
            
            logger.info(f"Starting Waitress production server with HTTPS on {Config.FLASK_HOST}:{Config.FLASK_PORT} with {threads} threads")
            server.run()
        else:
            logger.info(f"Starting Waitress production server on {Config.FLASK_HOST}:{Config.FLASK_PORT} with {threads} threads")
            serve(
                app, 
                host=Config.FLASK_HOST, 
                port=Config.FLASK_PORT,
                threads=threads
            )

if __name__ == '__main__':
    # Start monitoring service in a separate thread
    monitoring_thread = threading.Thread(
        target=start_monitoring_service,
        args=(monitoring_config, sources),
        daemon=True
    )
    monitoring_thread.start()
    
    # Start syslog server in a separate thread
    syslog_thread = threading.Thread(
        target=start_syslog_server,
        args=(sources,),
        daemon=True
    )
    syslog_thread.start()
    
    # Start web server
    start_web_server()