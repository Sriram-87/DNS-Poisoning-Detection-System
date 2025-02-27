#!/usr/bin/env python3
"""
Configuration module for DNS Poisoning Detection System.
"""

import json
import logging
import os

logger = logging.getLogger("DNS_Monitor")

class DNSMonitorConfig:
    """Configuration for DNS Monitor."""
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize configuration, loading from file if available."""
        self.config_file = config_file
        self.interface = None
        self.trusted_domains_file = "trusted_domains.json"
        self.alert_threshold = 3
        self.ttl_deviation_threshold = 0.5  # 50% deviation from normal
        self.min_ttl = 60  # Minimum acceptable TTL in seconds
        self.max_analysis_records = 100
        self.log_file = "dns_monitor.log"
        self.dashboard_enabled = False
        self.dashboard_port = 8080
        self.external_apis = []
        self.blacklisted_ips = []
        self.whitelisted_domains = []
        self.update_interval = 3600  # Update trusted domains every hour
        
        # Load configuration if file exists
        self.load_config()
    
    def load_config(self):
        """Load configuration from JSON file."""
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    
                # Update attributes from config file
                for key, value in config.items():
                    if hasattr(self, key):
                        setattr(self, key, value)
                logger.info(f"Configuration loaded from {self.config_file}")
            else:
                logger.warning(f"Configuration file {self.config_file} not found. Using defaults.")
                self.save_config()  # Create default config file
        except Exception as e:
            logger.error(f"Error loading configuration: {e}")
    
    def save_config(self):
        """Save current configuration to JSON file."""
        try:
            # Ensure directory exists
            config_dir = os.path.dirname(self.config_file)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir)
                
            config = {key: value for key, value in self.__dict__.items() 
                      if not key.startswith('_') and key != 'config_file'}
            
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
            logger.info(f"Configuration saved to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {e}")