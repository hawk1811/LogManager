#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Source Manager
This module handles the management of log sources, including starting and stopping them.
"""

import logging
import threading
import time
import queue
import atexit
import signal
import os

from core_handler import (
    global_sources, active_servers, folder_watchers, file_watchers,
    processing_queues, flush_all_metadata, initialize_metadata_flusher,
    initialize_resource_monitor
)
from syslog_server import start_udp_server
from file_watcher import start_folder_watcher, start_file_watcher

# Try to import Windows Event monitoring if available
try:
    from windows_event_monitor import start_event_watcher, stop_event_watcher, event_watchers
    WINDOWS_EVENT_AVAILABLE = True
except ImportError:
    WINDOWS_EVENT_AVAILABLE = False
    event_watchers = {}
    logging.warning("Windows Event monitoring module not available")

# Configure logging
logger = logging.getLogger(__name__)

def start_sources(sources):
    """
    Start servers and watchers for each source.
    
    Args:
        sources (dict): The source configurations
    """
    for source_id, source_config in sources.items():
        start_source(source_id, source_config)

def start_source(source_id, source_config):
    """
    Start server or watcher for a specific source.
    
    Args:
        source_id (str): The source ID
        source_config (dict): The source configuration
    """
    source_type = source_config.get('source_type', 'syslog')
    
    if source_type == 'syslog':
        # Start UDP server
        port = int(source_config.get('port', 514))
        
        # Stop existing server if any
        stop_source(source_id)
        
        # Log the attempt to start the server
        logger.info(f"Attempting to start UDP server for source {source_id} on port {port}")
        
        # Start new server with error handling
        try:
            server, thread = start_udp_server(source_id, port)
            if server and thread:
                active_servers[source_id] = (server, thread)
                logger.info(f"Successfully started UDP server for source {source_id} on port {port}")
            else:
                logger.error(f"Failed to start UDP server for source {source_id} on port {port} - server or thread is None")
        except Exception as e:
            logger.error(f"Exception while starting UDP server for source {source_id} on port {port}: {str(e)}", exc_info=True)
    
    elif source_type == 'folder':
        # Start folder watcher
        folder_path = source_config.get('folder_path')
        if folder_path:
            # Stop existing watcher if any
            stop_source(source_id)
            
            # Start new watcher
            observer, handler = start_folder_watcher(source_id, folder_path)
            if observer and handler:
                folder_watchers[source_id] = (observer, handler)
                logger.info(f"Started folder watcher for source {source_id} on {folder_path}")
    
    elif source_type == 'file':
        # Start file watcher
        file_path = source_config.get('file_path')
        if file_path:
            # Stop existing watcher if any
            stop_source(source_id)
            
            # Start new watcher
            observer, handler = start_file_watcher(source_id, file_path)
            if observer and handler:
                file_watchers[source_id] = (observer, handler)
                logger.info(f"Started file watcher for source {source_id} on {file_path}")
    
    elif source_type == 'windows_event':
        # Start Windows Event log watcher
        if WINDOWS_EVENT_AVAILABLE:
            # Stop existing watcher if any
            stop_source(source_id)
            
            # Start new watcher
            thread = start_event_watcher(source_id, source_config)
            if thread:
                event_watchers[source_id] = thread
                logger.info(f"Started Windows Event watcher for source {source_id}")
        else:
            logger.error(f"Windows Event monitoring not available. Required dependencies not met.")
    else:
        logger.warning(f"Unknown source type {source_type} for source {source_id}")

def stop_source(source_id):
    """
    Stop server or watcher for a specific source.
    
    Args:
        source_id (str): The source ID
    """
    # Stop UDP server if active
    if source_id in active_servers:
        server, thread = active_servers[source_id]
        try:
            server.shutdown()
            logger.info(f"Shutting down UDP server for source {source_id}")
            # Give it a moment to complete shutdown
            time.sleep(0.5)
        except Exception as e:
            logger.error(f"Error shutting down UDP server for source {source_id}: {str(e)}")
        del active_servers[source_id]
        logger.info(f"Stopped UDP server for source {source_id}")
    
    # Stop folder watcher if active
    if source_id in folder_watchers:
        observer, handler = folder_watchers[source_id]
        try:
            observer.stop()
            observer.join(timeout=1)
        except Exception as e:
            logger.error(f"Error stopping folder watcher for source {source_id}: {str(e)}")
        del folder_watchers[source_id]
        logger.info(f"Stopped folder watcher for source {source_id}")
    
    # Stop file watcher if active
    if source_id in file_watchers:
        observer, handler = file_watchers[source_id]
        try:
            observer.stop()
            observer.join(timeout=1)
        except Exception as e:
            logger.error(f"Error stopping file watcher for source {source_id}: {str(e)}")
        del file_watchers[source_id]
        logger.info(f"Stopped file watcher for source {source_id}")
    
    # Stop Windows Event watcher if active
    if WINDOWS_EVENT_AVAILABLE and source_id in event_watchers:
        # We can't directly stop threads in Python
        # The thread will stop when the source_id is removed from global_sources
        try:
            stop_event_watcher(source_id)
        except Exception as e:
            logger.error(f"Error stopping Windows Event watcher for source {source_id}: {str(e)}")
        if source_id in event_watchers:
            del event_watchers[source_id]
        logger.info(f"Stopped Windows Event watcher for source {source_id}")

def check_sources_periodically():
    """Periodically check if sources have changed and update servers/watchers."""
    
    while True:
        try:
            # Check for new or changed sources
            current_source_ids = set(global_sources.keys())
            active_source_ids = set(active_servers.keys()).union(
                set(folder_watchers.keys()),
                set(file_watchers.keys())
            )
            
            # Add event watchers if available
            if WINDOWS_EVENT_AVAILABLE:
                active_source_ids = active_source_ids.union(set(event_watchers.keys()))
            
            # Start sources that are not active
            for source_id in current_source_ids - active_source_ids:
                source_config = global_sources.get(source_id)
                if source_config:
                    logger.info(f"Starting inactive source: {source_id}")
                    start_source(source_id, source_config)
            
            # Stop sources that are no longer in the configuration
            for source_id in active_source_ids - current_source_ids:
                logger.info(f"Stopping removed source: {source_id}")
                stop_source(source_id)
            
            # Check for configuration changes in active sources
            for source_id in current_source_ids.intersection(active_source_ids):
                source_config = global_sources.get(source_id, {})
                source_type = source_config.get('source_type', 'syslog')
                
                # Check if source type has changed
                if (source_type == 'syslog' and source_id not in active_servers) or \
                   (source_type == 'folder' and source_id not in folder_watchers) or \
                   (source_type == 'file' and source_id not in file_watchers) or \
                   (source_type == 'windows_event' and WINDOWS_EVENT_AVAILABLE and source_id not in event_watchers):
                    logger.info(f"Source type changed for {source_id}, restarting")
                    stop_source(source_id)
                    start_source(source_id, source_config)
                
                # Check if specific settings have changed
                if source_type == 'syslog' and source_id in active_servers:
                    current_port = int(source_config.get('port', 514))
                    # Check if port has changed - since we can't easily extract the current port from the server
                    # we'll restart if we think settings may have changed
                    server, _ = active_servers.get(source_id, (None, None))
                    if server and hasattr(server, 'port') and server.port != current_port:
                        logger.info(f"Port changed for source {source_id}, restarting")
                        stop_source(source_id)
                        start_source(source_id, source_config)
                
                # For folder/file watchers, check if the path has changed and restart if needed
                if source_type == 'folder' and source_id in folder_watchers:
                    folder_path = source_config.get('folder_path')
                    # Need to check if the path has changed, but we don't have easy access to the current path
                    # For simplicity, restart if needed in a real implementation
                
                if source_type == 'file' and source_id in file_watchers:
                    file_path = source_config.get('file_path')
                    # Need to check if the path has changed, but we don't have easy access to the current path
                    # For simplicity, restart if needed in a real implementation
            
            # Wait before next check
            time.sleep(10)
        except Exception as e:
            logger.error(f"Error in check_sources_periodically: {str(e)}")
            time.sleep(30)  # Longer sleep on error

def initialize_signal_handlers():
    """Initialize signal handlers for graceful shutdown."""
    # Only register signal handlers in the main thread
    if threading.current_thread() is threading.main_thread():
        def signal_handler(signum, frame):
            logger.info(f"Received signal {signum}, shutting down...")
            flush_all_metadata()
            # Don't exit here, let the main thread handle the exit
        
        try:
            # Register signal handlers
            signal.signal(signal.SIGINT, signal_handler)
            signal.signal(signal.SIGTERM, signal_handler)
            logger.info("Registered signal handlers for graceful shutdown")
        except ValueError as e:
            # This occurs when trying to set signal handlers in non-main threads
            logger.warning(f"Could not initialize signal handlers: {str(e)}")
    else:
        logger.info("Signal handlers only work in main thread, skipping initialization")

def start_syslog_server(sources):
    """
    Start the syslog server to receive messages.
    
    Args:
        sources (dict): The source configurations
    """
    from log_processor import initialize_processing_pool, log_processor_worker
    
    # Update global sources
    global global_sources
    global_sources = sources
    
    # Initialize signal handlers
    initialize_signal_handlers()
    
    # Register shutdown handler to flush metadata
    atexit.register(flush_all_metadata)
    
    # Initialize processing pool
    initialize_processing_pool()
    
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Create processing queues for each source
    for source_id, source_config in sources.items():
        # Calculate optimal queue size
        from config import Config
        target_eps = getattr(Config, 'TARGET_EPS', 20000)
        queue_size = calculate_queue_size(target_eps)
        
        # Create queue
        processing_queues[source_id] = queue.Queue(maxsize=queue_size)
        
        # Make sure source directory exists if target type is file
        if source_config.get('target_type') == 'file':
            target_dir = source_config.get('target_directory', os.path.join('logs', source_id))
            os.makedirs(target_dir, exist_ok=True)
        
        # Start log processor worker for this source
        from core_handler import processing_pool
        if processing_pool is not None:
            try:
                processing_pool.submit(log_processor_worker, source_id)
                logger.info(f"Started log processor worker for source {source_id}")
            except Exception as e:
                logger.error(f"Failed to start log processor worker for source {source_id}: {str(e)}")
        else:
            # If processing pool is None, log the error and ensure we initialize it
            logger.error("Processing pool is not initialized. Attempting to initialize...")
            initialize_processing_pool()
            # Try again after initialization
            from core_handler import processing_pool
            if processing_pool is not None:
                try:
                    processing_pool.submit(log_processor_worker, source_id)
                    logger.info(f"Started log processor worker for source {source_id} after reinitialization")
                except Exception as e:
                    logger.error(f"Failed to start log processor worker after reinitialization: {str(e)}")
            else:
                logger.error("Processing pool initialization failed. Cannot start log processor worker.")

def calculate_queue_size(target_eps):
    """
    Calculate the optimal queue size based on target EPS.
    
    Args:
        target_eps (int): Target events per second
        
    Returns:
        int: Optimal queue size
    """
    # Queue should be able to handle bursts of events
    # A good rule of thumb is 2-5 seconds worth of events
    burst_multiplier = 3  # 3 seconds worth of events
    
    # Calculate queue size
    queue_size = target_eps * burst_multiplier
    
    # Cap queue size to avoid excessive memory usage
    max_queue_size = 100000  # 100K events
    
    return min(queue_size, max_queue_size)