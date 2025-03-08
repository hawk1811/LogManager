#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Core Handler
This module contains the core handler functions and global variables.
"""

import os
import json
import time
import logging
import threading
import psutil
import queue
from datetime import datetime
from collections import deque

# Configure logging
logger = logging.getLogger(__name__)

# Global variables shared across modules
global_sources = {}
source_locks = {}  # For thread-safe access to source metadata
active_servers = {}  # Track active UDP servers
folder_watchers = {}  # Track folder watchers
file_watchers = {}  # Track file watchers
file_positions = {}  # Track file positions for file watchers
processing_queues = {}  # Queues for log processing

# Initialize processing_pool with a small default pool to prevent NoneType errors
import concurrent.futures
processing_pool = concurrent.futures.ThreadPoolExecutor(max_workers=2, thread_name_prefix="DefaultLogProcessor")
# This will be properly initialized later, but this ensures it's never None

# Use a circular buffer for metadata updates to reduce memory pressure
# Maximum number of log entries to keep in memory per source
MAX_METADATA_ENTRIES = 10000  
source_metadata_buffers = {}  # In-memory buffers for log metadata

# Metadata flush intervals and lock
METADATA_FLUSH_INTERVAL = 10  # Seconds
metadata_flush_locks = {}
last_metadata_flush = {}

# System metrics tracking
system_metrics = {
    'cpu_percent': 0,
    'memory_percent': 0,
    'disk_percent': 0,
    'events_per_second': 0,
    'events_total': 0,
    'events_dropped': 0,
    'events_processed': 0,
    'timestamp': datetime.now().isoformat()
}

# Counters for events
event_counters = {
    'total': 0,
    'processed': 0,
    'dropped': 0,
    'last_update': time.time(),
    'recent_events': 0,
    'lock': threading.Lock()
}

def update_event_counter(event_type, count=1):
    """Update event counters in a thread-safe way."""
    with event_counters['lock']:
        event_counters[event_type] += count
        event_counters['recent_events'] += count
        
        # Calculate events per second every 5 seconds
        current_time = time.time()
        if current_time - event_counters['last_update'] >= 5:
            elapsed = current_time - event_counters['last_update']
            if elapsed > 0:  # Prevent division by zero
                system_metrics['events_per_second'] = round(event_counters['recent_events'] / elapsed, 2)
            system_metrics['events_total'] = event_counters['total']
            system_metrics['events_processed'] = event_counters['processed']
            system_metrics['events_dropped'] = event_counters['dropped']
            system_metrics['timestamp'] = datetime.now().isoformat()
            
            # Reset for next interval
            event_counters['recent_events'] = 0
            event_counters['last_update'] = current_time

def get_system_metrics():
    """
    Get current system metrics.
    
    Returns:
        dict: System metrics including CPU, memory, disk usage, and event rates
    """
    # Create a local copy to avoid modifying the global variable directly
    metrics = dict(system_metrics)
    
    try:
        # Update CPU metrics
        try:
            metrics['cpu_percent'] = psutil.cpu_percent(interval=0.1)
        except Exception:
            # Keep existing value or use default
            metrics['cpu_percent'] = metrics.get('cpu_percent', 0)
        
        # Update memory metrics
        try:
            metrics['memory_percent'] = psutil.virtual_memory().percent
        except Exception:
            # Keep existing value or use default
            metrics['memory_percent'] = metrics.get('memory_percent', 0)
        
        # Update disk metrics
        try:
            # Get disk usage with safeguards
            try:
                disk_usage = psutil.disk_usage('/')
                metrics['disk_percent'] = disk_usage.percent
            except Exception:
                # Try alternative approach if the standard one fails
                import shutil
                total, used, free = shutil.disk_usage('/')
                metrics['disk_percent'] = (used / total) * 100
        except Exception:
            # Keep existing value or use default
            metrics['disk_percent'] = metrics.get('disk_percent', 0)
        
        # Update timestamp
        metrics['timestamp'] = datetime.now().isoformat()
    except Exception:
        # If an unexpected error occurs, ensure we return at least the existing data
        pass
    
    return metrics

def collect_metrics_periodically():
    """Periodically collect system metrics."""
    while True:
        try:
            # Update system metrics
            get_system_metrics()
            
            # Wait before next collection
            time.sleep(5)
        except Exception as e:
            logger.error(f"Error in collect_metrics_periodically: {str(e)}")
            time.sleep(5)

def store_log(target_dir, timestamp, client_ip, message):
    """
    Store log message in a file.
    
    Args:
        target_dir (str): The target directory
        timestamp (datetime): The message timestamp
        client_ip (str): The client IP address
        message (str): The syslog message
        
    Returns:
        str: The log filename
    """
    try:
        # Create filename based on timestamp
        filename = f"{timestamp.strftime('%Y%m%d_%H%M%S')}_{timestamp.microsecond:06d}.log"
        filepath = os.path.join(target_dir, filename)
        
        # Store log with metadata
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(f"Timestamp: {timestamp.isoformat()}\n")
            f.write(f"Source IP: {client_ip}\n")
            f.write(f"Message: {message}\n")
        
        return filename
    except Exception as e:
        logger.error(f"Error storing log file in {target_dir}: {str(e)}")
        return None

def flush_metadata(source_id):
    """
    Flush metadata buffer to disk for a specific source.
    
    Args:
        source_id (str): The source ID
    """
    # Skip if no metadata to flush
    if source_id not in source_metadata_buffers or not source_metadata_buffers[source_id]:
        return
    
    # Get lock for this source
    if source_id not in metadata_flush_locks:
        metadata_flush_locks[source_id] = threading.Lock()
    
    lock = metadata_flush_locks[source_id]
    
    # Skip if another thread is already flushing
    if not lock.acquire(blocking=False):
        return
    
    try:
        # Skip if recently flushed
        now = time.time()
        last_flush = last_metadata_flush.get(source_id, 0)
        if now - last_flush < METADATA_FLUSH_INTERVAL and len(source_metadata_buffers[source_id]) < MAX_METADATA_ENTRIES:
            return
        
        # Load existing metadata
        metadata_file = os.path.join('data', f'{source_id}.json')
        metadata = []
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
            except (json.JSONDecodeError, FileNotFoundError, PermissionError) as e:
                logger.error(f"Error reading metadata file for source {source_id}: {str(e)}")
                # If file is corrupted, start with empty metadata
                metadata = []
        
        # Add buffered entries
        buffer = source_metadata_buffers[source_id]
        while buffer:
            metadata.append(buffer.popleft())
        
        # Limit the size of metadata to avoid memory issues
        if len(metadata) > MAX_METADATA_ENTRIES:
            metadata = metadata[-MAX_METADATA_ENTRIES:]
        
        # Save metadata
        try:
            with open(metadata_file, 'w', encoding='utf-8') as f:
                json.dump(metadata, f)
            
            # Update last flush time
            last_metadata_flush[source_id] = now
        except (PermissionError, IOError) as e:
            logger.error(f"Error writing metadata file for source {source_id}: {str(e)}")
            # Put entries back in buffer
            if buffer:
                buffer.extendleft(reversed(metadata[-len(buffer):]))
    except Exception as e:
        logger.error(f"Error flushing metadata for source {source_id}: {str(e)}")
    finally:
        lock.release()

def update_source_metadata(source_id, timestamp, log_filename):
    """
    Update source metadata with new log entry.
    
    Args:
        source_id (str): The source ID
        timestamp (datetime): The message timestamp
        log_filename (str): The log filename
    """
    if not log_filename:
        return
    
    try:
        # Initialize buffer for this source if needed
        if source_id not in source_metadata_buffers:
            source_metadata_buffers[source_id] = deque(maxlen=MAX_METADATA_ENTRIES)
        
        # Get target directory
        target_dir = global_sources[source_id].get('target_directory', os.path.join('logs', source_id))
        
        # Add new log entry to buffer
        source_metadata_buffers[source_id].append({
            'timestamp': timestamp.isoformat(),
            'filename': log_filename,
            'path': os.path.join(target_dir, log_filename)
        })
        
        # Check if we need to flush to disk
        buffer_size = len(source_metadata_buffers[source_id])
        if buffer_size >= MAX_METADATA_ENTRIES // 10:  # Flush when buffer is at least 10% full
            # Start a background thread to flush metadata
            thread = threading.Thread(target=flush_metadata, args=(source_id,), daemon=True)
            thread.start()
    except Exception as e:
        logger.error(f"Error updating source metadata for {source_id}: {str(e)}")

def get_source_stats(sources):
    """
    Get statistics for each source.
    
    Args:
        sources (dict): The source configurations
        
    Returns:
        dict: The source statistics
    """
    stats = {}
    
    for source_id, source_config in sources.items():
        try:
            metadata_file = os.path.join('data', f'{source_id}.json')
            log_count = 0
            last_log_time = None
            
            # First check in-memory buffer for most recent logs
            if source_id in source_metadata_buffers and source_metadata_buffers[source_id]:
                buffer = source_metadata_buffers[source_id]
                log_count += len(buffer)
                if buffer:
                    last_entry = buffer[-1]
                    last_log_time = last_entry.get('timestamp')
            
            # Then check persisted metadata
            if os.path.exists(metadata_file):
                try:
                    with open(metadata_file, 'r', encoding='utf-8') as f:
                        metadata = json.load(f)
                    
                    # Add saved log count (excluding any we already counted from buffer)
                    log_count += len(metadata)
                    
                    # Update last log time if we don't have one from buffer or if it's more recent
                    if metadata and (not last_log_time or last_log_time < metadata[-1].get('timestamp', '')):
                        last_log_time = metadata[-1].get('timestamp')
                except Exception as e:
                    logger.error(f"Error reading metadata for source {source_id}: {str(e)}")
            
            # Create stats
            stats[source_id] = source_config.copy()
            stats[source_id]['log_count'] = log_count
            stats[source_id]['last_log_time'] = last_log_time
            
            # Add server/watcher status
            if source_id in active_servers:
                stats[source_id]['status'] = 'active'
                stats[source_id]['server_type'] = 'udp'
            elif source_id in folder_watchers:
                stats[source_id]['status'] = 'active'
                stats[source_id]['server_type'] = 'folder'
            elif source_id in file_watchers:
                stats[source_id]['status'] = 'active'
                stats[source_id]['server_type'] = 'file'
            else:
                stats[source_id]['status'] = 'inactive'
        except Exception as e:
            logger.error(f"Error getting stats for source {source_id}: {str(e)}")
            stats[source_id] = source_config.copy()
            stats[source_id]['log_count'] = 0
            stats[source_id]['last_log_time'] = None
            stats[source_id]['status'] = 'error'
            stats[source_id]['error'] = str(e)
    
    return stats

def flush_all_metadata():
    """
    Flush all source metadata to disk.
    
    Call this before shutting down to ensure all metadata is persisted.
    """
    for source_id in list(source_metadata_buffers.keys()):
        try:
            flush_metadata(source_id)
        except Exception as e:
            logger.error(f"Error flushing metadata for source {source_id} during shutdown: {str(e)}")

def background_metadata_flusher():
    """
    Periodically flush metadata for all sources.
    This ensures metadata is regularly persisted even during high load scenarios.
    """
    while True:
        try:
            # Wait for interval
            time.sleep(METADATA_FLUSH_INTERVAL)
            
            # Flush metadata for all sources
            for source_id in list(source_metadata_buffers.keys()):
                if len(source_metadata_buffers[source_id]) > 0:
                    # Start a thread to avoid blocking
                    thread = threading.Thread(
                        target=flush_metadata, 
                        args=(source_id,), 
                        daemon=True,
                        name=f"metadata_flush_{source_id}"
                    )
                    thread.start()
                    
        except Exception as e:
            logger.error(f"Error in background metadata flusher: {str(e)}")
            time.sleep(30)  # Sleep longer on error

def initialize_metadata_flusher():
    """Initialize the background metadata flusher thread."""
    thread = threading.Thread(
        target=background_metadata_flusher,
        daemon=True,
        name="metadata_flusher"
    )
    thread.start()
    logger.info("Started background metadata flusher thread")

def resource_monitor():
    """
    Monitor system resources and log/alert when resources are constrained.
    This helps prevent system crashes due to resource exhaustion.
    """
    # Thresholds for resource alerts
    CPU_ALERT_THRESHOLD = 85  # Percent
    MEMORY_ALERT_THRESHOLD = 80  # Percent
    DISK_ALERT_THRESHOLD = 85  # Percent
    
    # Alert cooldown to prevent spamming logs
    last_cpu_alert = 0
    last_memory_alert = 0
    last_disk_alert = 0
    ALERT_COOLDOWN = 300  # Seconds between alerts
    
    while True:
        try:
            # Get current metrics
            metrics = get_system_metrics()
            now = time.time()
            
            # Check CPU usage
            if metrics['cpu_percent'] > CPU_ALERT_THRESHOLD and now - last_cpu_alert > ALERT_COOLDOWN:
                logger.warning(f"HIGH CPU USAGE ALERT: {metrics['cpu_percent']}% - System may be overloaded")
                last_cpu_alert = now
            
            # Check memory usage
            if metrics['memory_percent'] > MEMORY_ALERT_THRESHOLD and now - last_memory_alert > ALERT_COOLDOWN:
                logger.warning(f"HIGH MEMORY USAGE ALERT: {metrics['memory_percent']}% - Starting to drop messages")
                last_memory_alert = now
                
                # Take action to reduce memory pressure
                for source_id in list(source_metadata_buffers.keys()):
                    flush_metadata(source_id)
            
            # Check disk usage
            if metrics['disk_percent'] > DISK_ALERT_THRESHOLD and now - last_disk_alert > ALERT_COOLDOWN:
                logger.warning(f"HIGH DISK USAGE ALERT: {metrics['disk_percent']}% - Log storage may be affected")
                last_disk_alert = now
            
            # Wait before next check
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in resource monitor: {str(e)}")
            time.sleep(120)  # Sleep longer on error

def initialize_resource_monitor():
    """Initialize the resource monitor thread."""
    thread = threading.Thread(
        target=resource_monitor,
        daemon=True,
        name="resource_monitor"
    )
    thread.start()
    logger.info("Started resource monitor thread")