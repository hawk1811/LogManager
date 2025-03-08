#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Log Processor
This module handles the processing of logs from various sources.
"""

import os
import logging
import json
import time
import requests
import concurrent.futures
import queue
import re
from datetime import datetime
from dateutil import parser

from config import Config
from core_handler import (
    update_event_counter, global_sources, store_log,
    update_source_metadata, processing_queues, processing_pool
)
from utils import calculate_required_threads, calculate_queue_size

# Configure logging
logger = logging.getLogger(__name__)

# HEC connection pooling
hec_sessions = {}
HEC_SESSION_TIMEOUT = 5  # seconds
HEC_MAX_RETRIES = 3

def get_hec_session(hec_url):
    """Get or create a requests session for HEC connections."""
    if hec_url not in hec_sessions:
        session = requests.Session()
        # Configure session for optimal performance
        adapter = requests.adapters.HTTPAdapter(
            pool_connections=10,
            pool_maxsize=100,
            max_retries=HEC_MAX_RETRIES
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        hec_sessions[hec_url] = session
    
    return hec_sessions[hec_url]

def log_processor_worker(source_id):
    """
    Worker function for processing logs from the queue.
    
    Args:
        source_id (str): The source ID to process logs for
    """
    logger.info(f"Starting log processor worker for source {source_id}")
    
    # Track batch processing for HEC targets
    hec_batch = {}
    hec_batch_size = 50  # Number of events to batch before sending
    hec_batch_timeout = 1.0  # Seconds to wait before sending a partial batch
    hec_last_flush = time.time()
    
    while source_id in global_sources:
        try:
            # Get source configuration
            source_config = global_sources.get(source_id, {})
            
            if not source_config:
                # Source was removed, stop worker
                # Flush any remaining HEC batches
                for hec_url in hec_batch:
                    flush_hec_batch(hec_url, hec_batch[hec_url], source_id)
                break
            
            # Check if we need to flush HEC batches due to timeout
            now = time.time()
            if now - hec_last_flush > hec_batch_timeout:
                for hec_url in list(hec_batch.keys()):
                    if hec_batch[hec_url]:
                        flush_hec_batch(hec_url, hec_batch[hec_url], source_id)
                        hec_batch[hec_url] = []
                hec_last_flush = now
            
            # Get log data from queue with timeout
            try:
                log_data = processing_queues[source_id].get(timeout=0.5)
            except queue.Empty:
                # No data available, try again
                continue
            
            # Extract log data
            timestamp = log_data.get('timestamp')
            client_ip = log_data.get('client_ip')
            message = log_data.get('message')
            
            # Process based on target type
            target_type = source_config.get('target_type', 'file')
            
            if target_type == 'file':
                # Store in file
                target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
                
                # Make sure target directory exists
                os.makedirs(target_dir, exist_ok=True)
                
                # Store the log
                log_filename = store_log(target_dir, timestamp, client_ip, message)
                
                # Update source metadata
                update_source_metadata(source_id, timestamp, log_filename)
                
            elif target_type == 'hec':
                # Add to HEC batch for efficient sending
                hec_url = source_config.get('hec_url')
                hec_token = source_config.get('hec_token')
                
                if hec_url and hec_token:
                    # Initialize batch for this HEC URL if needed
                    if hec_url not in hec_batch:
                        hec_batch[hec_url] = []
                    
                    # Add event to batch
                    hec_event = prepare_hec_event(source_id, timestamp, client_ip, message, hec_token)
                    hec_batch[hec_url].append(hec_event)
                    
                    # Check if batch is ready to send
                    if len(hec_batch[hec_url]) >= hec_batch_size:
                        flush_hec_batch(hec_url, hec_batch[hec_url], source_id)
                        hec_batch[hec_url] = []
                        hec_last_flush = time.time()
            
            # Mark as processed and update counter
            processing_queues[source_id].task_done()
            update_event_counter('processed')
            
        except Exception as e:
            logger.error(f"Error in log processor worker for source {source_id}: {str(e)}")
            # Avoid tight loop if there's an error
            time.sleep(0.1)

def prepare_hec_event(source_id, timestamp, client_ip, message, hec_token):
    """Prepare an event for HEC submission."""
    return {
        "time": timestamp.timestamp() if hasattr(timestamp, 'timestamp') else time.time(),
        "host": client_ip,
        "source": source_id,
        "sourcetype": "syslog",
        "event": {
            "message": message,
            "timestamp": timestamp.isoformat() if hasattr(timestamp, 'isoformat') else str(timestamp),
            "source_ip": client_ip
        },
        "token": hec_token
    }

def flush_hec_batch(hec_url, batch_events, source_id):
    """
    Send a batch of events to HEC.
    
    Args:
        hec_url (str): The HEC endpoint URL
        batch_events (list): List of HEC event dictionaries
        source_id (str): The source ID for logging
    """
    if not batch_events:
        return
    
    try:
        # Get session
        session = get_hec_session(hec_url)
        
        # Extract token from first event
        hec_token = batch_events[0].get('token')
        
        # Prepare request
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }
        
        # Create JSON payload - use "\n" separated events for efficiency
        payload = "\n".join(json.dumps(event) for event in batch_events)
        
        # Send to HEC
        response = session.post(
            hec_url,
            headers=headers,
            data=payload,
            timeout=HEC_SESSION_TIMEOUT
        )
        
        # Check response
        if response.status_code != 200:
            logger.error(f"Error sending to HEC for source {source_id}: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error sending batch to HEC for source {source_id}: {str(e)}")

def send_to_hec(hec_url, hec_token, source_id, timestamp, client_ip, message):
    """
    Send log data to a HEC (HTTP Event Collector) endpoint.
    
    Args:
        hec_url (str): The HEC endpoint URL
        hec_token (str): The HEC authentication token
        source_id (str): The source ID
        timestamp (datetime): The message timestamp
        client_ip (str): The client IP address
        message (str): The log message
    """
    try:
        # Prepare HEC data
        hec_data = {
            "time": timestamp.timestamp(),
            "host": client_ip,
            "source": source_id,
            "sourcetype": "syslog",
            "event": {
                "message": message,
                "timestamp": timestamp.isoformat(),
                "source_ip": client_ip
            }
        }
        
        # Get session
        session = get_hec_session(hec_url)
        
        # Send to HEC
        headers = {
            "Authorization": f"Splunk {hec_token}",
            "Content-Type": "application/json"
        }
        
        # Use non-blocking requests with a timeout
        response = session.post(
            hec_url,
            headers=headers,
            json=hec_data,
            timeout=HEC_SESSION_TIMEOUT
        )
        
        # Check response
        if response.status_code != 200:
            logger.error(f"Error sending to HEC: {response.status_code} {response.text}")
    except Exception as e:
        logger.error(f"Error sending to HEC: {str(e)}")

def initialize_processing_pool():
    """Initialize the thread pool for log processing."""
    global processing_pool
    
    # Import psutil here to avoid circular imports
    import psutil
    import concurrent.futures
    
    # Determine optimal number of workers based on CPU cores and expected EPS
    cpu_count = psutil.cpu_count(logical=True)
    
    # Target EPS can be estimated from Config or dynamically determined
    from config import Config
    target_eps = getattr(Config, 'TARGET_EPS', 20000)
    
    # Calculate required threads
    worker_count = calculate_required_threads(target_eps)
    
    # Ensure we have at least one worker
    worker_count = max(1, worker_count)
    
    try:
        # Create thread pool with proper exception handling
        processing_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="LogProcessor"
        )
        
        logger.info(f"Initialized processing pool with {worker_count} workers")
    except Exception as e:
        logger.error(f"Failed to initialize processing pool: {str(e)}")
        # Create a minimal pool as fallback
        processing_pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4,
            thread_name_prefix="LogProcessor"
        )
        logger.info("Created fallback processing pool with 4 workers")

def parse_logs_for_timerange(source_id, start_time, end_time):
    """
    Parse logs for a specific source and time range.
    
    Args:
        source_id (str): The source ID
        start_time (str): The start time in ISO format
        end_time (str): The end time in ISO format
        
    Returns:
        list: The parsed log data
    """
    # Parse time range
    try:
        start_dt = parser.parse(start_time)
        end_dt = parser.parse(end_time)
    except Exception as e:
        logger.error(f"Error parsing time range: {str(e)}")
        raise ValueError(f"Invalid time format: {str(e)}")
    
    # Get metadata for this source
    metadata_file = os.path.join('data', f'{source_id}.json')
    if not os.path.exists(metadata_file):
        return []
    
    try:
        with open(metadata_file, 'r', encoding='utf-8') as f:
            metadata = json.load(f)
    except Exception as e:
        logger.error(f"Error reading metadata: {str(e)}")
        raise ValueError(f"Error reading source data: {str(e)}")
    
    # Optimize: Use binary search to find start index if sorted by timestamp
    # This improves performance for large log files
    logs_in_range = []
    
    # Check if metadata is sorted by timestamp (should be)
    if metadata and len(metadata) > 0:
        # Try to parse first and last timestamp to check sorting
        try:
            first_time = parser.parse(metadata[0].get('timestamp', ''))
            last_time = parser.parse(metadata[-1].get('timestamp', ''))
            
            # If sorted (ascending or descending)
            if first_time < last_time:  # Ascending
                # Binary search for start position
                start_idx = binary_search_timestamp(metadata, start_dt)
                for log_entry in metadata[start_idx:]:
                    try:
                        log_time = parser.parse(log_entry.get('timestamp', ''))
                        if log_time <= end_dt:
                            logs_in_range.append(log_entry)
                        else:
                            break  # Past end time, no need to continue
                    except Exception:
                        continue
            elif first_time > last_time:  # Descending
                # Binary search for end position (in reverse)
                end_idx = binary_search_timestamp(metadata, end_dt, descending=True)
                for log_entry in metadata[end_idx:]:
                    try:
                        log_time = parser.parse(log_entry.get('timestamp', ''))
                        if log_time >= start_dt:
                            logs_in_range.append(log_entry)
                        else:
                            break  # Before start time, no need to continue
                    except Exception:
                        continue
            else:
                # Not clearly sorted, use linear search
                for log_entry in metadata:
                    try:
                        log_time = parser.parse(log_entry.get('timestamp', ''))
                        if start_dt <= log_time <= end_dt:
                            logs_in_range.append(log_entry)
                    except Exception:
                        continue
        except Exception:
            # Error parsing timestamps, fall back to linear search
            for log_entry in metadata:
                try:
                    log_time = parser.parse(log_entry.get('timestamp', ''))
                    if start_dt <= log_time <= end_dt:
                        logs_in_range.append(log_entry)
                except Exception:
                    continue
    
    # Read and parse log content for the filtered logs (with batching for large results)
    max_batch_size = 1000  # Maximum number of logs to process at once
    parsed_logs = []
    
    for i in range(0, len(logs_in_range), max_batch_size):
        batch = logs_in_range[i:i+max_batch_size]
        
        for log_entry in batch:
            log_path = log_entry.get('path')
            if not log_path or not os.path.exists(log_path):
                continue
            
            try:
                with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                    log_content = f.read()
                
                # Parse log content
                timestamp_match = re.search(r'Timestamp: (.*)', log_content)
                source_ip_match = re.search(r'Source IP: (.*)', log_content)
                message_match = re.search(r'Message: (.*)', log_content)
                
                parsed_logs.append({
                    'timestamp': timestamp_match.group(1) if timestamp_match else '',
                    'source_ip': source_ip_match.group(1) if source_ip_match else '',
                    'message': message_match.group(1) if message_match else '',
                    'filename': os.path.basename(log_path)
                })
            except Exception as e:
                logger.error(f"Error parsing log file {log_path}: {str(e)}")
    
    return parsed_logs

def binary_search_timestamp(metadata, target_dt, descending=False):
    """
    Perform binary search on metadata to find the index of the first entry 
    with timestamp >= target_dt (or <= target_dt if descending).
    
    Args:
        metadata (list): The metadata list
        target_dt (datetime): The target datetime
        descending (bool): Whether the metadata is sorted in descending order
        
    Returns:
        int: The index of the first entry that matches the criteria
    """
    left, right = 0, len(metadata) - 1
    result = 0
    
    while left <= right:
        mid = (left + right) // 2
        
        try:
            mid_dt = parser.parse(metadata[mid].get('timestamp', ''))
            
            if (not descending and mid_dt < target_dt) or (descending and mid_dt > target_dt):
                left = mid + 1
                result = left
            else:
                right = mid - 1
                result = mid
        except Exception:
            # If we can't parse this timestamp, move left
            left = mid + 1
            result = left
    
    # Ensure result is within bounds
    return max(0, min(result, len(metadata) - 1))