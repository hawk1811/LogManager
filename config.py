#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Configuration
This module contains the configuration settings for the application.
"""

import os
import secrets

class Config:
    """Configuration class for the application."""
    
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
    FLASK_HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    FLASK_PORT = int(os.environ.get('FLASK_PORT', 5000))
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # Syslog server configuration
    SYSLOG_HOST = os.environ.get('SYSLOG_HOST', '0.0.0.0')
    SYSLOG_PORT = int(os.environ.get('SYSLOG_PORT', 514))
    
    # Application configuration
    MAX_MEMORY_USAGE = int(os.environ.get('MAX_MEMORY_USAGE', 80))  # Percentage of available system memory
    MAX_CPU_USAGE = int(os.environ.get('MAX_CPU_USAGE', 85))  # Percentage of available CPU
    LOG_ROTATION_SIZE = int(os.environ.get('LOG_ROTATION_SIZE', 10))  # Size in MB
    LOG_RETENTION_DAYS = int(os.environ.get('LOG_RETENTION_DAYS', 30))
    
    # Performance tuning
    TARGET_EPS = int(os.environ.get('TARGET_EPS', 20000))  # Target events per second
    BATCH_SIZE = int(os.environ.get('BATCH_SIZE', 100))  # Batch size for HEC submissions
    
    # Thread pool configuration
    MIN_THREADS = int(os.environ.get('MIN_THREADS', 4))  # Minimum number of worker threads
    MAX_THREADS = int(os.environ.get('MAX_THREADS', 100))  # Maximum number of worker threads
    
    # Queue configuration
    MAX_QUEUE_SIZE = int(os.environ.get('MAX_QUEUE_SIZE', 100000))  # Maximum queue size
    
    # Metadata configuration
    METADATA_FLUSH_INTERVAL = int(os.environ.get('METADATA_FLUSH_INTERVAL', 10))  # Seconds
    MAX_METADATA_ENTRIES = int(os.environ.get('MAX_METADATA_ENTRIES', 10000))  # Maximum number of metadata entries
    
    # Default credentials (only used for first login)
    DEFAULT_ADMIN_USERNAME = 'admin'
    DEFAULT_ADMIN_PASSWORD = 'password'
    
    # Directory paths
    DATA_DIR = os.environ.get('DATA_DIR', 'data')
    LOGS_DIR = os.environ.get('LOGS_DIR', 'logs')
    CERTS_DIR = os.environ.get('CERTS_DIR', 'certs')
    
    # SSL/TLS configuration
    SSL_CERT_FILE = os.path.join(CERTS_DIR, 'certificate.pem')
    SSL_KEY_FILE = os.path.join(CERTS_DIR, 'private_key.pem')
    
    # Create required directories if they don't exist
    @classmethod
    def initialize(cls):
        """Initialize required directories."""
        os.makedirs(cls.DATA_DIR, exist_ok=True)
        os.makedirs(cls.LOGS_DIR, exist_ok=True)
        os.makedirs(cls.CERTS_DIR, exist_ok=True)
        
        # Log configuration
        logger = logging.getLogger(__name__)
        logger.info(f"Initialized configuration with TARGET_EPS={cls.TARGET_EPS}")

# Import logging after class definition to avoid circular imports
import logging
Config.initialize()