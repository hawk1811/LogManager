#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - File Watcher
This module handles monitoring of local files and folders.
"""

import os
import logging
import time
import threading
from datetime import datetime

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False
    logging.warning("Watchdog module not found. File and folder watching will be done via polling.")
    # Define a minimal FileSystemEventHandler to avoid errors when watchdog is not available
    class FileSystemEventHandler:
        pass

from core_handler import update_event_counter, file_positions, processing_queues

# Configure logging
logger = logging.getLogger(__name__)

class FolderEventHandler(FileSystemEventHandler):
    """Handler for file system events in monitored folders."""
    
    def __init__(self, source_id):
        self.source_id = source_id
        self.creation_time = datetime.now()
    
    def on_created(self, event):
        """Handle file creation events."""
        if event.is_directory:
            return
        
        # Only process files created after the handler was initialized
        try:
            file_stat = os.stat(event.src_path)
            file_creation_time = datetime.fromtimestamp(file_stat.st_ctime)
            
            if file_creation_time >= self.creation_time:
                self.process_new_file(event.src_path)
        except Exception as e:
            logger.error(f"Error processing file creation event: {str(e)}")
    
    def on_modified(self, event):
        """Handle file modification events."""
        if event.is_directory:
            return
        
        # Check if this is a file we're already tracking
        if event.src_path in file_positions:
            self.process_file_changes(event.src_path)
    
    def process_new_file(self, file_path):
        """Process a newly created file."""
        try:
            logger.info(f"New file detected: {file_path}")
            
            # Start tracking this file
            file_positions[file_path] = 0
            
            # Process it
            self.process_file_changes(file_path)
        except Exception as e:
            logger.error(f"Error processing new file {file_path}: {str(e)}")
    
    def process_file_changes(self, file_path):
        """Process changes in a file."""
        try:
            if not os.path.exists(file_path):
                # File was deleted
                if file_path in file_positions:
                    del file_positions[file_path]
                return
            
            # Get current position
            current_position = file_positions.get(file_path, 0)
            
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                # Skip to the last position
                f.seek(current_position)
                
                # Read new content
                new_content = f.read()
                
                # Update position
                file_positions[file_path] = f.tell()
            
            if new_content:
                # Process new content line by line
                timestamp = datetime.now()
                client_ip = "127.0.0.1"  # Local source
                
                for line in new_content.splitlines():
                    if line.strip():
                        # Queue for processing
                        log_data = {
                            'source_id': self.source_id,
                            'timestamp': timestamp,
                            'client_ip': client_ip,
                            'message': line.strip(),
                            'file_path': file_path
                        }
                        
                        # Update total event counter
                        update_event_counter('total')
                        
                        # Put in queue
                        if self.source_id in processing_queues:
                            if processing_queues[self.source_id].full():
                                update_event_counter('dropped')
                                logger.warning(f"Queue full for source {self.source_id}, dropping message")
                            else:
                                processing_queues[self.source_id].put_nowait(log_data)
                        else:
                            update_event_counter('dropped')
                            logger.warning(f"No queue for source {self.source_id}, dropping message")
        except Exception as e:
            logger.error(f"Error processing file changes {file_path}: {str(e)}")

class PollingFileWatcher:
    """A polling-based file watcher for systems without watchdog."""
    
    def __init__(self, source_id, file_path=None, folder_path=None):
        self.source_id = source_id
        self.file_path = file_path
        self.folder_path = folder_path
        self.handler = FolderEventHandler(source_id)
        self.running = True
        self.known_files = set()
        self.file_mtimes = {}
        
        # Initialize known files and mtimes
        if file_path and os.path.exists(file_path):
            self.known_files.add(file_path)
            self.file_mtimes[file_path] = os.path.getmtime(file_path)
            # Start reading from the end of the file
            file_positions[file_path] = os.path.getsize(file_path)
        elif folder_path and os.path.exists(folder_path):
            self._scan_folder()
        
        # Start the polling thread
        self.thread = threading.Thread(target=self._poll, daemon=True)
        self.thread.start()
    
    def _scan_folder(self):
        """Scan folder for files."""
        if not self.folder_path or not os.path.exists(self.folder_path):
            return
        
        try:
            for root, _, files in os.walk(self.folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.known_files.add(file_path)
                    self.file_mtimes[file_path] = os.path.getmtime(file_path)
        except Exception as e:
            logger.error(f"Error scanning folder {self.folder_path}: {str(e)}")
    
    def _poll(self):
        """Poll for file changes."""
        while self.running:
            try:
                if self.file_path:
                    self._check_file(self.file_path)
                elif self.folder_path:
                    self._check_folder()
                
                # Sleep to reduce CPU usage
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error polling for file changes: {str(e)}")
                time.sleep(5)  # Longer sleep on error
    
    def _check_file(self, file_path):
        """Check a single file for changes."""
        if not os.path.exists(file_path):
            return
        
        current_mtime = os.path.getmtime(file_path)
        previous_mtime = self.file_mtimes.get(file_path)
        
        if previous_mtime is None:
            # New file
            self.file_mtimes[file_path] = current_mtime
            event = type('Event', (), {'is_directory': False, 'src_path': file_path})()
            self.handler.on_created(event)
        elif current_mtime > previous_mtime:
            # Modified file
            self.file_mtimes[file_path] = current_mtime
            event = type('Event', (), {'is_directory': False, 'src_path': file_path})()
            self.handler.on_modified(event)
    
    def _check_folder(self):
        """Check folder for new or modified files."""
        if not os.path.exists(self.folder_path):
            return
        
        new_known_files = set()
        
        for root, _, files in os.walk(self.folder_path):
            for file in files:
                file_path = os.path.join(root, file)
                new_known_files.add(file_path)
                
                self._check_file(file_path)
        
        # Check for deleted files
        for file_path in self.known_files - new_known_files:
            if file_path in file_positions:
                del file_positions[file_path]
        
        self.known_files = new_known_files
    
    def stop(self):
        """Stop the polling thread."""
        self.running = False
        self.thread.join(timeout=1)

def start_folder_watcher(source_id, folder_path):
    """
    Start a folder watcher for a specific source.
    
    Args:
        source_id (str): The source ID
        folder_path (str): The folder path to watch
        
    Returns:
        tuple: (observer, handler) or (None, None) if failed
    """
    if not WATCHDOG_AVAILABLE:
        try:
            # Use polling watcher instead
            watcher = PollingFileWatcher(source_id, folder_path=folder_path)
            logger.info(f"Started polling folder watcher for source {source_id} on {folder_path}")
            return watcher, watcher.handler
        except Exception as e:
            logger.error(f"Error starting polling folder watcher for source {source_id} on {folder_path}: {str(e)}")
            return None, None
    
    try:
        # Create event handler
        event_handler = FolderEventHandler(source_id)
        
        # Create observer
        observer = Observer()
        observer.schedule(event_handler, folder_path, recursive=True)
        observer.start()
        
        logger.info(f"Started folder watcher for source {source_id} on {folder_path}")
        return observer, event_handler
    except Exception as e:
        logger.error(f"Error starting folder watcher for source {source_id} on {folder_path}: {str(e)}")
        return None, None

def start_file_watcher(source_id, file_path):
    """
    Start a file watcher for a specific source.
    
    Args:
        source_id (str): The source ID
        file_path (str): The file path to watch
        
    Returns:
        tuple: (observer, handler) or (None, None) if failed
    """
    if not WATCHDOG_AVAILABLE:
        try:
            # Use polling watcher instead
            watcher = PollingFileWatcher(source_id, file_path=file_path)
            logger.info(f"Started polling file watcher for source {source_id} on {file_path}")
            return watcher, watcher.handler
        except Exception as e:
            logger.error(f"Error starting polling file watcher for source {source_id} on {file_path}: {str(e)}")
            return None, None
    
    try:
        # Get directory and filename
        directory = os.path.dirname(file_path)
        if not directory:
            directory = '.'
        
        # Create event handler
        event_handler = FolderEventHandler(source_id)
        
        # Initialize file position
        if os.path.exists(file_path):
            # Start reading from the end of the file
            file_positions[file_path] = os.path.getsize(file_path)
        
        # Create observer
        observer = Observer()
        observer.schedule(event_handler, directory, recursive=False)
        observer.start()
        
        logger.info(f"Started file watcher for source {source_id} on {file_path}")
        return observer, event_handler
    except Exception as e:
        logger.error(f"Error starting file watcher for source {source_id} on {file_path}: {str(e)}")
        return None, None