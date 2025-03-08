#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Monitoring Module
This module handles application monitoring and reporting.
"""

import os
import json
import time
import logging
import threading
import socket
import psutil
import requests
from datetime import datetime

from config import Config
from core_handler import get_system_metrics, global_sources
from syslog_server import check_port_availability
from utils import (
    check_memory_usage, check_cpu_usage, check_disk_usage, 
    get_disk_stats, get_memory_stats, rotate_logs
)

# Configure logging
logger = logging.getLogger(__name__)

# Global monitoring configuration
monitoring_config = {
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

# Monitoring state
monitoring_thread = None
monitoring_active = False
monitoring_lock = threading.Lock()
last_sent_time = None

# Session for HEC connections
hec_session = None

def get_hec_session():
    """Get a persistent session for HEC connections."""
    global hec_session
    if hec_session is None:
        hec_session = requests.Session()
        # Configure session for optimal performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=5,
            pool_maxsize=10,
            max_retries=3
        )
        hec_session.mount('http://', adapter)
        hec_session.mount('https://', adapter)
    return hec_session

def update_monitoring_config(new_config):
    """
    Update the monitoring configuration.
    
    Args:
        new_config (dict): The new monitoring configuration
    """
    global monitoring_config, monitoring_active
    
    with monitoring_lock:
        # Update configuration
        monitoring_config.update(new_config)
        
        # Update monitoring state
        if monitoring_config.get("enabled") and monitoring_config.get("hec_url") and monitoring_config.get("hec_token"):
            monitoring_active = True
        else:
            monitoring_active = False
    
    logger.info(f"Updated monitoring configuration. Active: {monitoring_active}")

def get_listening_ports():
    """
    Get a list of UDP ports currently being listened on.
    
    Returns:
        list: List of UDP ports
    """
    ports = []
    try:
        # Get all network connections
        connections = psutil.net_connections(kind='udp4')
        
        # Extract listening UDP ports
        for conn in connections:
            if conn.laddr.port not in ports:
                ports.append(conn.laddr.port)
    except Exception as e:
        logger.error(f"Error getting listening ports: {str(e)}")
    
    return ports

def get_active_sources_count(sources):
    """
    Get the count of active sources by type.
    
    Args:
        sources (dict): The source configurations
        
    Returns:
        dict: Counts of active sources by type
    """
    counts = {
        'total': 0,
        'syslog': 0,
        'folder': 0,
        'file': 0
    }
    
    try:
        for source_id, source_config in sources.items():
            counts['total'] += 1
            
            source_type = source_config.get('source_type')
            if source_type in counts:
                counts[source_type] += 1
    except Exception as e:
        logger.error(f"Error counting active sources: {str(e)}")
    
    return counts

def collect_monitoring_data(sources):
    """
    Collect monitoring data for the application.
    
    Args:
        sources (dict): The source configurations
        
    Returns:
        dict: Monitoring data
    """
    try:
        # Get hostname
        hostname = socket.gethostname()
        
        # Create base monitoring data
        data = {
            "timestamp": datetime.now().isoformat(),
            "hostname": hostname,
            "status": "OK"
        }
        
        # Add system metrics if enabled
        if monitoring_config.get('monitor_system', True):
            system_data = {"cpu_percent": 0, "memory_percent": 0, "disk_percent": 0}
            
            try:
                # Get system metrics
                metrics = get_system_metrics()
                system_data.update({
                    "cpu_percent": metrics.get('cpu_percent', 0),
                    "memory_percent": metrics.get('memory_percent', 0),
                    "disk_percent": metrics.get('disk_percent', 0),
                })
            except Exception as e:
                logger.error(f"Error getting system metrics for monitoring: {str(e)}")
            
            # Get detailed resource statistics
            try:
                disk_stats = get_disk_stats()
                system_data["disk_stats"] = disk_stats
            except Exception as e:
                logger.error(f"Error getting disk stats for monitoring: {str(e)}")
                system_data["disk_stats"] = {
                    'total': 'Unknown', 'used': 'Unknown', 
                    'free': 'Unknown', 'percent': 0
                }
            
            try:
                memory_stats = get_memory_stats()
                system_data["memory_stats"] = memory_stats
            except Exception as e:
                logger.error(f"Error getting memory stats for monitoring: {str(e)}")
                system_data["memory_stats"] = {
                    'total': 'Unknown', 'available': 'Unknown', 
                    'used': 'Unknown', 'percent': 0
                }
            
            data["system"] = system_data
        
        # Add event metrics if enabled
        if monitoring_config.get('monitor_events', True):
            try:
                metrics = get_system_metrics()
                data["events"] = {
                    "per_second": metrics.get('events_per_second', 0),
                    "total": metrics.get('events_total', 0),
                    "processed": metrics.get('events_processed', 0),
                    "dropped": metrics.get('events_dropped', 0)
                }
            except Exception as e:
                logger.error(f"Error getting event metrics for monitoring: {str(e)}")
                data["events"] = {
                    "per_second": 0, "total": 0, 
                    "processed": 0, "dropped": 0
                }
        
        # Add source information if enabled
        if monitoring_config.get('monitor_sources', True):
            try:
                # Get listening ports
                ports = get_listening_ports()
                
                # Get active sources count
                source_counts = get_active_sources_count(sources)
                
                data["sources"] = source_counts
                data["ports"] = ports
            except Exception as e:
                logger.error(f"Error getting source information for monitoring: {str(e)}")
                data["sources"] = {"total": 0, "syslog": 0, "folder": 0, "file": 0}
                data["ports"] = []
        
        # Add thread information if enabled
        if monitoring_config.get('monitor_threads', False):
            try:
                thread_count = threading.active_count()
                thread_names = [t.name for t in threading.enumerate()]
                
                data["threads"] = {
                    "count": thread_count,
                    "active_threads": thread_names[:10]  # Limit to first 10 threads
                }
            except Exception as e:
                logger.error(f"Error getting thread information for monitoring: {str(e)}")
                data["threads"] = {"count": 0, "active_threads": []}
        
        # Add custom fields if any
        custom_fields = monitoring_config.get('custom_fields', {})
        if custom_fields:
            data["custom"] = custom_fields
        
        # Add alerts if enabled
        if monitoring_config.get('monitor_alerts', True):
            try:
                alerts = []
                metrics = get_system_metrics()
                
                if metrics.get('cpu_percent', 0) > 80:
                    alerts.append("High CPU usage")
                
                if metrics.get('memory_percent', 0) > 80:
                    alerts.append("High memory usage")
                
                if metrics.get('disk_percent', 0) > 80:
                    alerts.append("High disk usage")
                
                if metrics.get('events_dropped', 0) > 1000:
                    alerts.append(f"High number of dropped events: {metrics.get('events_dropped')}")
                
                if alerts:
                    data["status"] = "WARNING"
                    data["alerts"] = alerts
            except Exception as e:
                logger.error(f"Error checking alerts for monitoring: {str(e)}")
        
        return data
    except Exception as e:
        logger.error(f"Error collecting monitoring data: {str(e)}")
        return {
            "timestamp": datetime.now().isoformat(),
            "hostname": socket.gethostname(),
            "status": "ERROR",
            "error": str(e)
        }

def send_monitoring_data(data):
    """
    Send monitoring data to the configured HEC endpoint.
    
    Args:
        data (dict): The monitoring data to send
        
    Returns:
        bool: True if successful, False otherwise
    """
    global last_sent_time
    
    if not monitoring_active:
        return False
    
    try:
        # Prepare HEC data
        hec_data = {
            "time": time.time(),
            "host": data.get("hostname", socket.gethostname()),
            "source": "syslog_manager_monitoring",
            "sourcetype": "monitoring",
            "event": data
        }
        
        # Send to HEC
        headers = {
            "Authorization": f"Splunk {monitoring_config.get('hec_token')}",
            "Content-Type": "application/json"
        }
        
        # Use persistent session
        session = get_hec_session()
        
        # Use non-blocking requests with a timeout
        response = session.post(
            monitoring_config.get('hec_url'),
            headers=headers,
            json=hec_data,
            timeout=5  # 5 second timeout
        )
        
        # Check response
        if response.status_code != 200:
            logger.error(f"Error sending monitoring data: {response.status_code} {response.text}")
            return False
        
        # Update last sent time
        last_sent_time = time.time()
        
        return True
    except Exception as e:
        logger.error(f"Error sending monitoring data: {str(e)}")
        return False

def perform_log_rotation():
    """Perform log rotation based on configured retention period."""
    try:
        # Get log retention days from config
        retention_days = getattr(Config, 'LOG_RETENTION_DAYS', 30)
        
        # Rotate logs in the logs directory
        count = rotate_logs('logs', max_age_days=retention_days)
        
        if count > 0:
            logger.info(f"Log rotation completed: {count} files deleted")
    except Exception as e:
        logger.error(f"Error performing log rotation: {str(e)}")

def monitoring_worker(sources):
    """
    Worker function for the monitoring thread.
    
    Args:
        sources (dict): The source configurations
    """
    global monitoring_active
    
    logger.info("Starting monitoring worker")
    
    # Track last log rotation time
    last_rotation = time.time()
    rotation_interval = 86400  # 24 hours
    
    # Track last data sent time
    last_data_sent = time.time()
    last_status = True  # True for success, False for failure
    
    while True:
        try:
            # Check if monitoring is active
            if monitoring_active:
                # Collect monitoring data
                data = collect_monitoring_data(sources)
                
                # Get monitoring interval
                interval = max(10, monitoring_config.get('interval', 60))
                
                # Check if it's time to send data
                now = time.time()
                if now - last_data_sent >= interval:
                    # Send monitoring data
                    success = send_monitoring_data(data)
                    last_data_sent = now
                    
                    # Log status change
                    if success != last_status:
                        if success:
                            logger.info("Monitoring data sending resumed successfully")
                        else:
                            logger.warning("Failed to send monitoring data")
                        last_status = success
            
            # Check if it's time for log rotation
            now = time.time()
            if now - last_rotation > rotation_interval:
                perform_log_rotation()
                last_rotation = now
            
            # Wait before next check
            time.sleep(1)
        except Exception as e:
            logger.error(f"Error in monitoring worker: {str(e)}")
            time.sleep(60)  # Wait a minute before trying again

def start_monitoring_service(config, sources):
    """
    Start the monitoring service.
    
    Args:
        config (dict): The monitoring configuration
        sources (dict): The source configurations
    """
    global monitoring_thread, monitoring_config
    
    # Update configuration
    update_monitoring_config(config)
    
    # Start monitoring thread
    monitoring_thread = threading.Thread(
        target=monitoring_worker,
        args=(sources,),
        daemon=True,
        name="monitoring_worker"
    )
    monitoring_thread.start()
    
    logger.info("Started monitoring service")

def get_monitoring_status():
    """
    Get current monitoring status.
    
    Returns:
        dict: Monitoring status and config
    """
    global monitoring_active, monitoring_config, monitoring_thread, last_sent_time
    
    status = {
        "active": monitoring_active,
        "config": monitoring_config.copy(),
        "thread_running": monitoring_thread is not None and monitoring_thread.is_alive() if monitoring_thread else False,
        "last_sent_time": last_sent_time
    }
    
    return status