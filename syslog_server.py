#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SyslogManager - Syslog Server
This module handles the UDP server for receiving syslog messages.
"""

import logging
import socketserver
import socket
import re
import threading
import select
import time
from datetime import datetime
from dateutil import parser

from core_handler import update_event_counter, global_sources
from utils import check_memory_usage, is_ip_in_network
from config import Config

# Configure logging
logger = logging.getLogger(__name__)

# Global list of active ports to prevent binding to the same port twice
active_ports = set()

def check_port_availability(port, host='0.0.0.0'):
    """
    Check if a port is available on the specified host.
    
    Args:
        port (int): Port number to check
        host (str): Host IP to bind to
        
    Returns:
        bool: True if port is available, False otherwise
    """
    # Check if port is already used by our application
    if port in active_ports:
        logger.warning(f"Port {port} is already in our active ports list.")
        return False
    
    try:
        # Check if port is already in use by creating a temporary socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.close()
        return True
    except OSError as e:
        # Port is already in use
        logger.error(f"Port {port} is not available: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Error checking port availability: {str(e)}")
        return False

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    """
    UDP handler for syslog messages.
    Processes incoming syslog messages and stores them in the appropriate files.
    """
    
    def handle(self):
        """Handle incoming syslog message."""
        try:
            # Get data and client address
            data = bytes.decode(self.request[0].strip(), 'utf-8', errors='replace')
            socket = self.request[1]
            client_address = self.client_address[0]
            
            # Process the syslog message
            self.process_syslog(client_address, data)
            
        except Exception as e:
            logger.error(f"Error handling syslog message: {str(e)}", exc_info=True)
    
    def process_syslog(self, client_ip, message):
        """
        Process a syslog message and store it in the appropriate file.
        
        Args:
            client_ip (str): The IP address of the client sending the message
            message (str): The syslog message content
        """
        # Skip if memory usage is too high
        if check_memory_usage() > Config.MAX_MEMORY_USAGE:
            logger.warning("Memory usage too high, dropping syslog message")
            update_event_counter('dropped')
            return
        
        # Parse timestamp from syslog message (RFC3164/RFC5424 formats)
        timestamp = self.extract_timestamp(message)
        if not timestamp:
            timestamp = datetime.now()
        
        # Find matching source for this client IP
        source_id = self.find_matching_source(client_ip)
        if not source_id:
            # No matching source found, drop the message
            update_event_counter('dropped')
            logger.warning(f"No matching source found for client IP {client_ip}, dropping message")
            return
        
        # Get source configuration
        source_config = global_sources.get(source_id, {})
        logger.debug(f"Found matching source {source_id} for client IP {client_ip}")
        
        # Add to processing queue
        try:
            from core_handler import processing_queues
            
            log_data = {
                'source_id': source_id,
                'timestamp': timestamp,
                'client_ip': client_ip,
                'message': message
            }
            
            # Update total event counter
            update_event_counter('total')
            
            # Put in queue with timeout to avoid blocking
            if source_id in processing_queues:
                if processing_queues[source_id].full():
                    # Queue is full, drop the message
                    update_event_counter('dropped')
                    logger.warning(f"Queue full for source {source_id}, dropping message")
                else:
                    processing_queues[source_id].put_nowait(log_data)
                    logger.debug(f"Message from {client_ip} queued for source {source_id}")
            else:
                # No queue for this source, drop the message
                update_event_counter('dropped')
                logger.warning(f"No queue for source {source_id}, dropping message")
        except Exception as e:
            update_event_counter('dropped')
            logger.error(f"Error queuing message: {str(e)}")
    
    def extract_timestamp(self, message):
        """
        Extract timestamp from syslog message.
        
        Args:
            message (str): The syslog message
            
        Returns:
            datetime: The extracted timestamp or None if not found
        """
        # Try RFC5424 format first: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        rfc5424_pattern = r'^<\d+>\d+ (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+|-)\d{2}:\d{2}) '
        rfc5424_match = re.search(rfc5424_pattern, message)
        if rfc5424_match:
            try:
                return parser.parse(rfc5424_match.group(1))
            except Exception:
                pass
        
        # Try RFC3164 format: <PRI>TIMESTAMP HOSTNAME
        rfc3164_pattern = r'^<\d+>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        rfc3164_match = re.search(rfc3164_pattern, message)
        if rfc3164_match:
            try:
                # Add current year as RFC3164 doesn't include it
                current_year = datetime.now().year
                timestamp_str = f"{rfc3164_match.group(1)} {current_year}"
                return parser.parse(timestamp_str)
            except Exception:
                pass
        
        # No timestamp found, return None
        return None
    
    def find_matching_source(self, client_ip):
        """
        Find the source configuration that matches the client IP.
        
        Args:
            client_ip (str): The client IP address
            
        Returns:
            str: The source ID or None if not found
        """
        for source_id, source_config in global_sources.items():
            if source_config.get('source_type') != 'syslog':
                continue
                
            source_ip = source_config.get('source_ip')
            if source_ip and is_ip_in_network(client_ip, source_ip):
                return source_id
        
        return None

class AsyncUDPServer:
    """
    Asynchronous UDP server that can handle multiple connections efficiently.
    This implementation provides better performance for high volume syslog traffic.
    """
    
    def __init__(self, host, port, source_id, existing_sock=None):
        self.host = host
        self.port = port
        self.source_id = source_id
        self.running = False
        self.server_thread = None
        self.sock = existing_sock
        
        # Track if this port is active
        global active_ports
        active_ports.add(port)
        
        logger.info(f"Initialized AsyncUDPServer for source {source_id} on {host}:{port}")
    
    def serve_forever(self):
        """Run the server until shutdown is called."""
        try:
            # Create socket if not provided
            if self.sock is None:
                logger.info(f"Creating new socket for {self.host}:{self.port}")
                self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                
                # Set socket buffer size to handle high-volume traffic
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB buffer
                
                # Bind socket to port
                try:
                    self.sock.bind((self.host, self.port))
                    logger.info(f"Socket bound to {self.host}:{self.port}")
                except Exception as e:
                    logger.error(f"Failed to bind to {self.host}:{self.port}: {str(e)}")
                    if self.sock:
                        self.sock.close()
                    return
            
            # Mark server as running
            self.running = True
            logger.info(f"UDP server running on {self.host}:{self.port} for source {self.source_id}")
            
            # Process incoming messages
            while self.running:
                # Check for messages with timeout
                try:
                    ready = select.select([self.sock], [], [], 0.1)  # 100ms timeout
                    
                    if ready[0]:
                        # Get message
                        data, addr = self.sock.recvfrom(8192)  # 8KB buffer
                        logger.debug(f"Received data from {addr[0]}:{addr[1]} on port {self.port}")
                        
                        # Process message
                        try:
                            message = data.decode('utf-8', errors='replace').strip()
                            client_ip = addr[0]
                            
                            # Process syslog message
                            self.process_message(client_ip, message)
                        except Exception as e:
                            logger.error(f"Error processing UDP message: {str(e)}")
                except Exception as e:
                    logger.error(f"Error in select() or recvfrom(): {str(e)}")
                    if not self.running:
                        break
                    time.sleep(0.1)  # Small delay to avoid tight loop on error
        except Exception as e:
            logger.error(f"Error in AsyncUDPServer: {str(e)}")
        finally:
            if self.sock:
                logger.info(f"Closing socket for {self.host}:{self.port}")
                self.sock.close()
            
            # Remove port from active ports
            if self.port in active_ports:
                active_ports.remove(self.port)
    
    def process_message(self, client_ip, message):
        """Process a received syslog message."""
        # Skip if memory usage is too high
        if check_memory_usage() > Config.MAX_MEMORY_USAGE:
            logger.warning("Memory usage too high, dropping syslog message")
            update_event_counter('dropped')
            return
        
        # Parse timestamp
        timestamp = self.extract_timestamp(message)
        if not timestamp:
            timestamp = datetime.now()
        
        # Find matching source for this client IP
        source_id = self.find_matching_source(client_ip)
        if not source_id:
            # If no specific source matches, use the generic source ID for this server
            source_id = self.source_id
        
        # Add to processing queue
        try:
            from core_handler import processing_queues
            
            log_data = {
                'source_id': source_id,
                'timestamp': timestamp,
                'client_ip': client_ip,
                'message': message
            }
            
            # Update total event counter
            update_event_counter('total')
            
            # Put in queue with timeout to avoid blocking
            if source_id in processing_queues:
                if processing_queues[source_id].full():
                    # Queue is full, drop the message
                    update_event_counter('dropped')
                    logger.warning(f"Queue full for source {source_id}, dropping message")
                else:
                    processing_queues[source_id].put_nowait(log_data)
                    logger.debug(f"Queued message from {client_ip} for source {source_id}")
            else:
                # No queue for this source, drop the message
                update_event_counter('dropped')
                logger.warning(f"No queue for source {source_id}, dropping message")
        except Exception as e:
            update_event_counter('dropped')
            logger.error(f"Error queuing message: {str(e)}")
    
    def extract_timestamp(self, message):
        """Extract timestamp from syslog message."""
        # Try RFC5424 format first: <PRI>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID
        rfc5424_pattern = r'^<\d+>\d+ (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+|-)\d{2}:\d{2}) '
        rfc5424_match = re.search(rfc5424_pattern, message)
        if rfc5424_match:
            try:
                return parser.parse(rfc5424_match.group(1))
            except Exception:
                pass
        
        # Try RFC3164 format: <PRI>TIMESTAMP HOSTNAME
        rfc3164_pattern = r'^<\d+>([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
        rfc3164_match = re.search(rfc3164_pattern, message)
        if rfc3164_match:
            try:
                # Add current year as RFC3164 doesn't include it
                current_year = datetime.now().year
                timestamp_str = f"{rfc3164_match.group(1)} {current_year}"
                return parser.parse(timestamp_str)
            except Exception:
                pass
        
        # No timestamp found, return None
        return None
    
    def find_matching_source(self, client_ip):
        """Find the source ID that matches the client IP."""
        for source_id, source_config in global_sources.items():
            if source_config.get('source_type') != 'syslog':
                continue
                
            source_ip = source_config.get('source_ip')
            if source_ip and is_ip_in_network(client_ip, source_ip):
                return source_id
        
        return None
    
    def shutdown(self):
        """Shutdown the server."""
        logger.info(f"Shutting down UDP server for source {self.source_id} on port {self.port}")
        self.running = False
        
        # Wait for server thread to complete
        if self.server_thread and self.server_thread.is_alive():
            self.server_thread.join(timeout=1)
            
        # Close socket if needed
        if self.sock:
            try:
                self.sock.close()
            except Exception as e:
                logger.error(f"Error closing socket: {str(e)}")
            self.sock = None
        
        # Remove port from active ports
        if self.port in active_ports:
            active_ports.remove(self.port)
        
        logger.info(f"UDP server for source {self.source_id} on port {self.port} shut down")

def start_udp_server(source_id, port):
    """
    Start a UDP server for a specific source on a specific port.
    
    Args:
        source_id (str): The source ID
        port (int): The port to listen on
        
    Returns:
        tuple: (server, thread) or (None, None) if failed
    """
    import threading
    
    try:
        # Check if port is available
        if not check_port_availability(port):
            logger.error(f"Port {port} is not available for source {source_id}")
            return None, None
        
        # Log attempt to start server
        logger.info(f"Setting up UDP server for source {source_id} on port {port}")
        
        # Create and configure socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Set socket buffer size to handle high-volume traffic
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024 * 1024)  # 1MB buffer
        
        # Bind socket to port
        try:
            sock.bind(('0.0.0.0', port))
            logger.info(f"Successfully bound socket to port {port} for source {source_id}")
        except Exception as e:
            logger.error(f"Failed to bind socket to port {port} for source {source_id}: {str(e)}")
            sock.close()
            # Remove port from active ports if binding failed
            if port in active_ports:
                active_ports.remove(port)
            return None, None
        
        # Create server object with the bound socket
        server = AsyncUDPServer('0.0.0.0', port, source_id, sock)
        
        # Start server in a separate thread
        server_thread = threading.Thread(
            target=server.serve_forever,
            daemon=True,
            name=f"syslog_server_{source_id}_{port}"
        )
        server_thread.start()
        
        # Store thread in server
        server.server_thread = server_thread
        
        logger.info(f"Started UDP server thread for source {source_id} on port {port}")
        return server, server_thread
    except Exception as e:
        logger.error(f"Error starting UDP server for source {source_id} on port {port}: {str(e)}", exc_info=True)
        # Make sure port is removed from active ports list if there was an error
        if port in active_ports:
            active_ports.remove(port)
        return None, None