#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Authentication Module
This module handles user authentication.
"""

import os
import json
import logging
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from config import Config

logger = logging.getLogger(__name__)

# Use a more compatible hash method
HASH_METHOD = 'pbkdf2:sha256'

class User(UserMixin):
    """User class for authentication."""
    
    def __init__(self, id, password_hash, must_change_password=False):
        self.id = id
        self.password_hash = password_hash
        self.must_change_password = must_change_password

def init_users():
    """Initialize users from the users.json file or create default admin user."""
    users = {}
    
    if os.path.exists('data/users.json'):
        try:
            with open('data/users.json', 'r') as f:
                user_data = json.load(f)
                
            for user_id, user_info in user_data.items():
                users[user_id] = User(
                    id=user_id,
                    password_hash=user_info['password_hash'],
                    must_change_password=user_info.get('must_change_password', False)
                )
        except Exception as e:
            logger.error(f"Error loading users: {str(e)}")
            # If there's an error, fall back to creating default admin
    
    # If no users exist, create default admin user
    if not users:
        admin_id = Config.DEFAULT_ADMIN_USERNAME
        password_hash = generate_password_hash(Config.DEFAULT_ADMIN_PASSWORD, method=HASH_METHOD)
        
        users[admin_id] = User(
            id=admin_id,
            password_hash=password_hash,
            must_change_password=True
        )
        
        save_users(users)
        logger.info("Created default admin user")
    
    return users

def save_users(users):
    """Save users to the users.json file."""
    user_data = {}
    
    for user_id, user in users.items():
        user_data[user_id] = {
            'password_hash': user.password_hash,
            'must_change_password': user.must_change_password
        }
    
    try:
        with open('data/users.json', 'w') as f:
            json.dump(user_data, f, indent=4)
    except Exception as e:
        logger.error(f"Error saving users: {str(e)}")