#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Windows Event Viewer Monitor
This module monitors Windows Event Viewer logs and processes them like other log sources.
"""

import os
import sys
import logging
import time
import threading
import json
import queue
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET

# Import third-party libraries
try:
    import Evtx.Evtx as evtx
    import Evtx.Views as views
    EVTX_AVAILABLE = True
except ImportError:
    EVTX_AVAILABLE = False
    logging.warning("python-evtx module not found. Windows Event log monitoring will be disabled.")

from core_handler import (
    update_event_counter, 
    processing_queues, 
    update_source_metadata,
    global_sources
)

# Configure logging
logger = logging.getLogger(__name__)

# Global state
event_watchers = {}
last_event_timestamps = {}
windows_event_channels = {
    'System': r'C:\Windows\System32\winevt\Logs\System.evtx',
    'Application': r'C:\Windows\System32\winevt\Logs\Application.evtx',
    'Security': r'C:\Windows\System32\winevt\Logs\Security.evtx',
    'Setup': r'C:\Windows\System32\winevt\Logs\Setup.evtx',
    'ForwardedEvents': r'C:\Windows\System32\winevt\Logs\ForwardedEvents.evtx'
}

# Severity mapping from Windows to Syslog
severity_mapping = {
    'Information': 'info',
    'Warning': 'warning',
    'Error': 'error',
    'Critical': 'critical',
    'Verbose': 'debug'
}

def is_windows():
    """Check if the system is Windows."""
    return sys.platform.startswith('win')

def get_available_event_logs():
    """
    Get a list of available Windows Event logs.
    
    Returns:
        dict: Dictionary of available logs with their paths
    """
    if not is_windows():
        return {}
    
    available_logs = {}
    
    for channel, path in windows_event_channels.items():
        if os.path.exists(path):
            available_logs[channel] = path
    
    return available_logs

def parse_evtx_record(record):
    """
    Parse an EVTX record into a structured format.
    
    Args:
        record: The EVTX record to parse
        
    Returns:
        dict: Structured record data
    """
    try:
        xml_str = record.xml()
        root = ET.fromstring(xml_str)
        
        # Extract system metadata
        system = root.find('./System')
        
        # Extract basic fields
        event_id = system.find('./EventID').text
        provider = system.find('./Provider').get('Name', 'Unknown')
        computer = system.find('./Computer').text if system.find('./Computer') is not None else 'Unknown'
        time_created = system.find('./TimeCreated').get('SystemTime') if system.find('./TimeCreated') is not None else None
        
        # Extract level (severity)
        level_node = system.find('./Level')
        level_map = {
            '0': 'LogAlways',
            '1': 'Critical',
            '2': 'Error',
            '3': 'Warning',
            '4': 'Information',
            '5': 'Verbose'
        }
        level = level_map.get(level_node.text, 'Unknown') if level_node is not None else 'Unknown'
        
        # Extract event data
        event_data = {}
        data_node = root.find('./EventData')
        if data_node is not None:
            for data in data_node.findall('./Data'):
                name = data.get('Name')
                value = data.text
                if name and value:
                    event_data[name] = value
                elif value:
                    # If no name is provided, use a generic name
                    event_data[f'Data_{len(event_data)}'] = value
        
        # Create structured record
        parsed_record = {
            'EventID': event_id,
            'Provider': provider,
            'Computer': computer,
            'TimeCreated': time_created,
            'Level': level,
            'Data': event_data
        }
        
        return parsed_record
    except Exception as e:
        logger.error(f"Error parsing EVTX record: {str(e)}")
        return {
            'EventID': 'Unknown',
            'Provider': 'Error',
            'Computer': 'Unknown',
            'TimeCreated': datetime.now().isoformat(),
            'Level': 'Error',
            'Data': {'Error': str(e)}
        }

def format_event_for_syslog(event_data):
    """
    Format Windows Event data for syslog-compatible output.
    
    Args:
        event_data (dict): Parsed event data
        
    Returns:
        str: Formatted syslog message
    """
    # Extract basic fields
    event_id = event_data.get('EventID', 'Unknown')
    provider = event_data.get('Provider', 'Unknown')
    level = event_data.get('Level', 'Information')
    computer = event_data.get('Computer', 'Unknown')
    
    # Format event data
    data_str = ''
    for key, value in event_data.get('Data', {}).items():
        data_str += f"{key}=\"{value}\" "
    
    # Create syslog-compatible message
    message = f"Windows-{provider}[{event_id}]: {level} on {computer} {data_str}"
    
    return message

def monitor_windows_event_log(source_id, config):
    """
    Monitor a Windows Event log and process new events.
    
    Args:
        source_id (str): The source ID
        config (dict): The source configuration
    """
    if not EVTX_AVAILABLE or not is_windows():
        logger.error(f"Windows Event monitoring not available. Required dependencies not met.")
        return
    
    try:
        # Get configuration
        event_log = config.get('event_log', 'System')
        min_level = config.get('min_level', 'Information')
        include_providers = config.get('include_providers', '').split(',')
        exclude_providers = config.get('exclude_providers', '').split(',')
        
        # Clean up provider lists
        include_providers = [p.strip() for p in include_providers if p.strip()]
        exclude_providers = [p.strip() for p in exclude_providers if p.strip()]
        
        # Get log path
        log_path = windows_event_channels.get(event_log)
        if not log_path or not os.path.exists(log_path):
            logger.error(f"Windows Event log '{event_log}' not found at path: {log_path}")
            return
        
        # Set up severity filter based on min_level
        severity_levels = ['Verbose', 'Information', 'Warning', 'Error', 'Critical']
        try:
            min_level_index = severity_levels.index(min_level)
            allowed_levels = severity_levels[min_level_index:]
        except ValueError:
            # Default to all levels if min_level is invalid
            allowed_levels = severity_levels
        
        # Initialize last_timestamp if not already set
        if source_id not in last_event_timestamps:
            # Default to events from the last hour
            last_event_timestamps[source_id] = (datetime.utcnow() - timedelta(hours=1)).isoformat()
        
        logger.info(f"Starting Windows Event monitor for {event_log} with min level {min_level}")
        
        while source_id in global_sources:
            try:
                # Open the .evtx file
                with evtx.Evtx(log_path) as log:
                    # Process events from newest to oldest
                    for record in log.records():
                        try:
                            # Parse record
                            parsed_record = parse_evtx_record(record)
                            
                            # Check timestamp
                            time_created = parsed_record.get('TimeCreated')
                            if not time_created or time_created <= last_event_timestamps[source_id]:
                                continue
                            
                            # Check level
                            level = parsed_record.get('Level')
                            if level not in allowed_levels:
                                continue
                            
                            # Check provider filters
                            provider = parsed_record.get('Provider')
                            if include_providers and provider not in include_providers:
                                continue
                            if provider in exclude_providers:
                                continue
                            
                            # Format for syslog
                            message = format_event_for_syslog(parsed_record)
                            
                            # Update last timestamp
                            last_event_timestamps[source_id] = time_created
                            
                            # Process message
                            process_event_log_message(source_id, message, parsed_record)
                        except Exception as e:
                            logger.error(f"Error processing event record: {str(e)}")
                
                # Wait before checking again
                time.sleep(10)  # Check every 10 seconds
            except Exception as e:
                logger.error(f"Error monitoring Windows Event log {event_log}: {str(e)}")
                time.sleep(30)  # Wait longer on error
    except Exception as e:
        logger.error(f"Error in Windows Event monitor for source {source_id}: {str(e)}")

def process_event_log_message(source_id, message, event_data):
    """
    Process a Windows Event log message.
    
    Args:
        source_id (str): The source ID
        message (str): The formatted message
        event_data (dict): The parsed event data
    """
    try:
        # Create timestamp from event data or use current time
        timestamp = datetime.fromisoformat(event_data.get('TimeCreated').replace('Z', '+00:00')) if event_data.get('TimeCreated') else datetime.now()
        
        # Use the computer name as the client IP
        client_ip = event_data.get('Computer', 'localhost')
        
        # Get source configuration
        source_config = global_sources.get(source_id, {})
        
        # Create log data
        log_data = {
            'source_id': source_id,
            'timestamp': timestamp,
            'client_ip': client_ip,
            'message': message,
            'event_data': event_data
        }
        
        # Update total event counter
        update_event_counter('total')
        
        # Put in queue for processing
        if source_id in processing_queues:
            if processing_queues[source_id].full():
                update_event_counter('dropped')
                logger.warning(f"Queue full for source {source_id}, dropping event message")
            else:
                processing_queues[source_id].put_nowait(log_data)
        else:
            update_event_counter('dropped')
            logger.warning(f"No queue for source {source_id}, dropping event message")
    except Exception as e:
        logger.error(f"Error processing Windows Event message: {str(e)}")
        update_event_counter('dropped')

def start_event_watcher(source_id, config):
    """
    Start a Windows Event log watcher for a specific source.
    
    Args:
        source_id (str): The source ID
        config (dict): The source configuration
        
    Returns:
        threading.Thread: The watcher thread
    """
    if not EVTX_AVAILABLE or not is_windows():
        logger.warning(f"Windows Event monitoring not available. python-evtx module not found or not running on Windows.")
        return None
    
    try:
        # Create and start thread
        thread = threading.Thread(
            target=monitor_windows_event_log,
            args=(source_id, config),
            daemon=True,
            name=f"event_watcher_{source_id}"
        )
        thread.start()
        
        logger.info(f"Started Windows Event watcher for source {source_id}")
        return thread
    except Exception as e:
        logger.error(f"Error starting Windows Event watcher for source {source_id}: {str(e)}")
        return None

def stop_event_watcher(source_id):
    """
    Stop a Windows Event log watcher for a specific source.
    
    Args:
        source_id (str): The source ID
    """
    if source_id in event_watchers:
        # We can't directly stop threads in Python
        # The thread will stop when the source_id is removed from global_sources
        logger.info(f"Marked Windows Event watcher for source {source_id} for termination")
        # Clean up references
        del event_watchers[source_id]