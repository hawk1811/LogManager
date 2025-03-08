#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Utility Functions
This module contains utility functions used throughout the application.
"""

import os
import ipaddress
import psutil
import logging
import time
import threading
import math

logger = logging.getLogger(__name__)

# Cache for resource checks to avoid frequent polling
resource_cache = {
    'memory': {'value': 0, 'timestamp': 0},
    'cpu': {'value': 0, 'timestamp': 0},
    'disk': {'value': 0, 'timestamp': 0}
}
resource_cache_lock = threading.Lock()
CACHE_TTL = 5  # seconds

def check_memory_usage():
    """
    Check the current memory usage of the system.
    Uses caching to improve performance.
    
    Returns:
        float: Memory usage percentage (0-100)
    """
    try:
        with resource_cache_lock:
            now = time.time()
            if now - resource_cache['memory']['timestamp'] > CACHE_TTL:
                resource_cache['memory']['value'] = psutil.virtual_memory().percent
                resource_cache['memory']['timestamp'] = now
            return resource_cache['memory']['value']
    except Exception as e:
        logger.error(f"Error checking memory usage: {str(e)}")
        return 0

def check_cpu_usage():
    """
    Check the current CPU usage of the system.
    Uses caching to improve performance.
    
    Returns:
        float: CPU usage percentage (0-100)
    """
    try:
        with resource_cache_lock:
            now = time.time()
            if now - resource_cache['cpu']['timestamp'] > CACHE_TTL:
                resource_cache['cpu']['value'] = psutil.cpu_percent(interval=0.1)
                resource_cache['cpu']['timestamp'] = now
            return resource_cache['cpu']['value']
    except Exception as e:
        logger.error(f"Error checking CPU usage: {str(e)}")
        return 0

def check_disk_usage(path='/'):
    """
    Check the current disk usage of the system.
    Uses caching to improve performance.
    
    Args:
        path (str): The path to check
        
    Returns:
        float: Disk usage percentage (0-100)
    """
    try:
        with resource_cache_lock:
            now = time.time()
            if now - resource_cache['disk']['timestamp'] > CACHE_TTL:
                resource_cache['disk']['value'] = psutil.disk_usage(path).percent
                resource_cache['disk']['timestamp'] = now
            return resource_cache['disk']['value']
    except Exception as e:
        logger.error(f"Error checking disk usage: {str(e)}")
        return 0

def is_ip_in_network(ip, network_spec):
    """
    Check if an IP address is in a network specification.
    
    Args:
        ip (str): The IP address to check
        network_spec (str): The network specification (IP, CIDR, or range)
        
    Returns:
        bool: True if the IP is in the network, False otherwise
    """
    try:
        # If network_spec is empty, return False
        if not network_spec or not ip:
            logger.warning(f"Empty IP or network specification: IP={ip}, Network={network_spec}")
            return False
        
        # Handle special cases like "all" or "*" to match any IP
        if network_spec.lower() in ('all', '*', 'any'):
            return True
            
        # Convert to IPv4Address for comparison
        try:
            check_ip = ipaddress.IPv4Address(ip)
        except ValueError:
            logger.error(f"Invalid IP address format: {ip}")
            return False
            
        # Check if it's a range (format: 192.168.1.1-192.168.1.10)
        if '-' in network_spec:
            try:
                start_ip, end_ip = network_spec.split('-')
                start_ip = ipaddress.IPv4Address(start_ip.strip())
                end_ip = ipaddress.IPv4Address(end_ip.strip())
                return start_ip <= check_ip <= end_ip
            except ValueError as e:
                logger.error(f"Error parsing IP range {network_spec}: {e}")
                return False
                
        # Check if it's a CIDR notation (e.g., 192.168.1.0/24)
        if '/' in network_spec:
            try:
                network = ipaddress.IPv4Network(network_spec, strict=False)
                return check_ip in network
            except ValueError as e:
                logger.error(f"Error parsing CIDR {network_spec}: {e}")
                return False
                
        # Check if it's a comma-separated list (e.g., 192.168.1.1, 10.0.0.1)
        if ',' in network_spec:
            for single_ip in network_spec.split(','):
                single_ip = single_ip.strip()
                if is_ip_in_network(ip, single_ip):  # Recursive call for each IP
                    return True
            return False
            
        # Check if it's a single IP
        try:
            return check_ip == ipaddress.IPv4Address(network_spec.strip())
        except ValueError as e:
            logger.error(f"Error parsing single IP {network_spec}: {e}")
            return False
    except Exception as e:
        logger.error(f"Error checking IP in network: {str(e)}")
        return False

def get_eps_resource_requirements():
    """
    Get resource requirements for different EPS levels.
    
    Returns:
        dict: Resource requirements for different EPS levels
    """
    return {
        "1000": {
            "cpu_cores": 2,
            "memory_gb": 4,
            "disk_iops": 500,
            "network_mbps": 10
        },
        "5000": {
            "cpu_cores": 4,
            "memory_gb": 8,
            "disk_iops": 1000,
            "network_mbps": 25
        },
        "10000": {
            "cpu_cores": 8,
            "memory_gb": 16,
            "disk_iops": 2000,
            "network_mbps": 50
        },
        "15000": {
            "cpu_cores": 12,
            "memory_gb": 24,
            "disk_iops": 3000,
            "network_mbps": 75
        },
        "20000": {
            "cpu_cores": 16,
            "memory_gb": 32,
            "disk_iops": 4000,
            "network_mbps": 100
        }
    }

def calculate_required_threads(eps):
    """
    Calculate the required number of worker threads based on EPS.
    
    Args:
        eps (int): Events per second
        
    Returns:
        int: Required number of worker threads
    """
    try:
        # Calculate based on CPU cores and EPS
        cpu_count = psutil.cpu_count(logical=True)
        
        # Baseline: 1 thread per 1000 EPS
        baseline_threads = math.ceil(eps / 1000)
        
        # Scale based on CPU cores
        if eps <= 1000:
            return max(4, min(cpu_count, baseline_threads * 2))
        elif eps <= 5000:
            return max(8, min(cpu_count * 2, baseline_threads * 2))
        elif eps <= 10000:
            return max(16, min(cpu_count * 3, baseline_threads * 1.5))
        elif eps <= 15000:
            return max(24, min(cpu_count * 4, baseline_threads * 1.25))
        else:  # Up to 20000
            return max(32, min(cpu_count * 5, baseline_threads))
    except Exception as e:
        logger.error(f"Error calculating required threads: {str(e)}")
        # Default to CPU count × 2 if there's an error
        return max(4, psutil.cpu_count(logical=True) * 2)

def calculate_queue_size(eps):
    """
    Calculate the required queue size based on EPS.
    
    Args:
        eps (int): Events per second
        
    Returns:
        int: Required queue size
    """
    # Queue should be able to handle at least 5-10 seconds of events
    # Higher EPS should have proportionally larger queues
    if eps <= 1000:
        return eps * 10  # 10 seconds
    elif eps <= 5000:
        return eps * 8   # 8 seconds
    elif eps <= 10000:
        return eps * 6   # 6 seconds
    elif eps <= 15000:
        return eps * 5   # 5 seconds
    else:  # Up to 20000
        return eps * 4   # 4 seconds

def check_system_resources(required_eps):
    """
    Check if the system has enough resources to handle the required EPS.
    
    Args:
        required_eps (int): Required events per second
        
    Returns:
        tuple: (bool, str) - (has_enough_resources, reason)
    """
    try:
        # Get requirements for the closest EPS level
        requirements = None
        eps_levels = [1000, 5000, 10000, 15000, 20000]
        
        for level in eps_levels:
            if required_eps <= level:
                requirements = get_eps_resource_requirements()[str(level)]
                break
        
        if not requirements:
            # If EPS is higher than our highest level, use the highest level
            requirements = get_eps_resource_requirements()["20000"]
        
        # Check CPU cores
        cpu_count = psutil.cpu_count(logical=True)
        if cpu_count < requirements["cpu_cores"]:
            return False, f"Insufficient CPU cores: {cpu_count} available, {requirements['cpu_cores']} required"
        
        # Check memory
        memory_gb = psutil.virtual_memory().total / (1024 * 1024 * 1024)
        if memory_gb < requirements["memory_gb"]:
            return False, f"Insufficient memory: {memory_gb:.1f} GB available, {requirements['memory_gb']} GB required"
        
        # TODO: Check disk IOPS - this requires more complex tests
        
        # TODO: Check network bandwidth - this requires more complex tests
        
        return True, "System has sufficient resources"
    except Exception as e:
        logger.error(f"Error checking system resources: {str(e)}")
        return False, f"Error checking system resources: {str(e)}"

def format_bytes(size):
    """
    Format bytes into a human-readable string.
    
    Args:
        size (int or float): Size in bytes
        
    Returns:
        str: Formatted string
    """
    try:
        # Ensure size is a valid number
        size = float(size)
        
        # Handle negative values
        if size < 0:
            return "0.00 B"
            
        # Define units and thresholds
        units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
        
        if size == 0:
            return "0.00 B"
            
        # Calculate the appropriate unit
        i = 0
        while size >= 1024 and i < len(units) - 1:
            size /= 1024.0
            i += 1
            
        # Format with 2 decimal places
        return f"{size:.2f} {units[i]}"
    except Exception:
        # Quietly handle all exceptions and return a fallback value
        return "Unknown"

def get_disk_stats(path='/'):
    """
    Get disk space statistics.
    
    Args:
        path (str): The path to check
        
    Returns:
        dict: Disk statistics
    """
    try:
        disk_usage = psutil.disk_usage(path)
        
        # Create the result dictionary with safe values
        result = {
            'total': "Unknown",
            'used': "Unknown",
            'free': "Unknown",
            'percent': 0
        }
        
        # Format each value separately to isolate potential errors
        try:
            result['total'] = format_bytes(disk_usage.total)
        except Exception:
            pass
            
        try:
            result['used'] = format_bytes(disk_usage.used)
        except Exception:
            pass
            
        try:
            result['free'] = format_bytes(disk_usage.free)
        except Exception:
            pass
            
        try:
            result['percent'] = float(disk_usage.percent)
        except Exception:
            pass
            
        return result
    except Exception:
        # Return a safe fallback dictionary
        return {
            'total': "Unknown",
            'used': "Unknown",
            'free': "Unknown",
            'percent': 0
        }

def get_memory_stats():
    """
    Get memory statistics.
    
    Returns:
        dict: Memory statistics
    """
    try:
        memory = psutil.virtual_memory()
        
        # Create the result dictionary with safe values
        result = {
            'total': "Unknown",
            'available': "Unknown",
            'used': "Unknown",
            'percent': 0
        }
        
        # Format each value separately to isolate potential errors
        try:
            result['total'] = format_bytes(memory.total)
        except Exception:
            pass
            
        try:
            result['available'] = format_bytes(memory.available)
        except Exception:
            pass
            
        try:
            result['used'] = format_bytes(memory.used)
        except Exception:
            pass
            
        try:
            result['percent'] = float(memory.percent)
        except Exception:
            pass
            
        return result
    except Exception:
        # Return a safe fallback dictionary
        return {
            'total': "Unknown",
            'available': "Unknown",
            'used': "Unknown",
            'percent': 0
        }

def rotate_logs(directory, max_age_days=30, dry_run=False):
    """
    Rotate logs based on age.
    
    Args:
        directory (str): The directory containing log files
        max_age_days (int): Maximum age of logs in days
        dry_run (bool): If True, don't actually delete files
        
    Returns:
        int: Number of files deleted
    """
    try:
        if not os.path.exists(directory):
            return 0
        
        # Calculate cutoff time
        cutoff_time = time.time() - (max_age_days * 24 * 60 * 60)
        count = 0
        
        for root, _, files in os.walk(directory):
            for file in files:
                if file.endswith('.log'):
                    file_path = os.path.join(root, file)
                    
                    # Check if file is older than cutoff
                    file_time = os.path.getmtime(file_path)
                    if file_time < cutoff_time:
                        if dry_run:
                            logger.info(f"Would delete old log file: {file_path}")
                        else:
                            try:
                                os.remove(file_path)
                                logger.info(f"Deleted old log file: {file_path}")
                                count += 1
                            except Exception as e:
                                logger.error(f"Error deleting log file {file_path}: {str(e)}")
        
        return count
    except Exception as e:
        logger.error(f"Error rotating logs: {str(e)}")
        return 0