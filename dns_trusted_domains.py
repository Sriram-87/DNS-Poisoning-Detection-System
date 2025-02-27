#!/usr/bin/env python3
"""
Trusted domains manager for DNS Poisoning Detection System.
"""

import json
import logging
import os
import socket
import threading
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Tuple

logger = logging.getLogger("DNS_Monitor")

# Try to import required dependencies with helpful error messages
try:
    import requests
except ImportError:
    logger.error("Error: 'requests' package not installed. Please install it using: pip install requests")
    raise ImportError("Missing 'requests' package")

class TrustedDomainsManager:
    """Manages trusted domain-to-IP mappings."""
    
    def __init__(self, config):
        """Initialize trusted domains manager."""
        self.config = config
        self.trusted_domains: Dict[str, Dict] = {}
        self.domain_history: Dict[str, List[Dict]] = defaultdict(list)
        self.update_lock = threading.Lock()
        self.load_trusted_domains()
    
    def load_trusted_domains(self):
        """Load trusted domains from JSON file."""
        try:
            if os.path.exists(self.config.trusted_domains_file):
                with open(self.config.trusted_domains_file, 'r') as f:
                    self.trusted_domains = json.load(f)
                logger.info(f"Loaded {len(self.trusted_domains)} trusted domains from {self.config.trusted_domains_file}")
            else:
                logger.warning(f"Trusted domains file {self.config.trusted_domains_file} not found. Creating empty file.")
                # Ensure directory exists
                domains_dir = os.path.dirname(self.config.trusted_domains_file)
                if domains_dir and not os.path.exists(domains_dir):
                    os.makedirs(domains_dir)
                self.save_trusted_domains()
        except Exception as e:
            logger.error(f"Error loading trusted domains: {e}")
            # Initialize with empty dictionary if loading fails
            self.trusted_domains = {}
    
    def save_trusted_domains(self):
        """Save trusted domains to JSON file."""
        try:
            # Ensure directory exists
            domains_dir = os.path.dirname(self.config.trusted_domains_file)
            if domains_dir and not os.path.exists(domains_dir):
                os.makedirs(domains_dir)
                
            with open(self.config.trusted_domains_file, 'w') as f:
                json.dump(self.trusted_domains, f, indent=4)
            logger.info(f"Saved {len(self.trusted_domains)} trusted domains to {self.config.trusted_domains_file}")
        except Exception as e:
            logger.error(f"Error saving trusted domains: {e}")
    
    def is_domain_trusted(self, domain: str) -> bool:
        """Check if a domain is in the trusted domains list."""
        return domain in self.trusted_domains
    
    def are_ips_trusted(self, domain: str, ips: List[str]) -> Tuple[bool, List[str]]:
        """
        Check if resolved IPs match trusted IPs for a domain.
        
        Returns:
            Tuple of (is_trusted, untrusted_ips)
        """
        if not self.is_domain_trusted(domain):
            # For new domains, all IPs are considered untrusted initially
            return False, ips
        
        trusted_ips = self.trusted_domains[domain].get("ips", [])
        untrusted_ips = [ip for ip in ips if ip not in trusted_ips]
        
        return len(untrusted_ips) == 0, untrusted_ips
    
    def is_ttl_suspicious(self, domain: str, ttl: int) -> bool:
        """
        Check if TTL is suspiciously different from the trusted TTL.
        
        Returns:
            True if TTL is suspicious, False otherwise
        """
        if not self.is_domain_trusted(domain):
            # For new domains, check if TTL is below minimum threshold
            return ttl < self.config.min_ttl
        
        trusted_ttl = self.trusted_domains[domain].get("ttl", 0)
        
        # If no trusted TTL yet, accept any reasonable TTL
        if trusted_ttl == 0:
            return ttl < self.config.min_ttl
        
        # Calculate deviation
        if trusted_ttl > 0:
            deviation = abs(ttl - trusted_ttl) / trusted_ttl
            return deviation > self.config.ttl_deviation_threshold or ttl < self.config.min_ttl
        
        return False
    
    def update_domain(self, domain: str, ips: List[str], ttl: int, source: str = "observed"):
        """Update or add a domain with its associated IPs and TTL."""
        with self.update_lock:
            current_time = datetime.now().isoformat()
            
            # Record this observation in history
            record = {
                "timestamp": current_time,
                "ips": ips,
                "ttl": ttl,
                "source": source
            }
            
            self.domain_history[domain].append(record)
            
            # Limit history size
            if len(self.domain_history[domain]) > self.config.max_analysis_records:
                self.domain_history[domain] = self.domain_history[domain][-self.config.max_analysis_records:]
            
            # If domain is new, add it to trusted domains
            if domain not in self.trusted_domains:
                self.trusted_domains[domain] = {
                    "ips": ips,
                    "ttl": ttl,
                    "first_seen": current_time,
                    "last_updated": current_time,
                    "update_count": 1
                }
            else:
                # Update existing domain
                current_domain = self.trusted_domains[domain]
                
                # Only update IPs if not from external validation
                if source == "validated" or current_domain.get("update_count", 0) < 5:
                    # For new domains (less than 5 updates), update IPs
                    # For established domains, only update if validated
                    current_domain["ips"] = list(set(ips))
                
                # Update TTL with a weighted average to avoid rapid fluctuations
                if current_domain.get("ttl", 0) > 0:
                    weight = 0.8  # Weight for existing TTL value
                    current_domain["ttl"] = int(current_domain["ttl"] * weight + ttl * (1 - weight))
                else:
                    current_domain["ttl"] = ttl
                
                current_domain["last_updated"] = current_time
                current_domain["update_count"] = current_domain.get("update_count", 0) + 1
            
            # Save after updates
            self.save_trusted_domains()
    
    def update_from_apis(self):
        """Update trusted domains from external APIs."""
        for api_config in self.config.external_apis:
            try:
                url = api_config.get("url")
                if not url:
                    continue
                
                logger.info(f"Updating trusted domains from API: {url}")
                response = requests.get(url, timeout=30)
                response.raise_for_status()
                
                data = response.json()
                
                # Process data according to API format
                domains_data = api_config.get("parser", {}).get("path", "domains")
                domains_list = self._extract_data_by_path(data, domains_data)
                
                if not domains_list or not isinstance(domains_list, list):
                    logger.warning(f"No domains data found from API: {url}")
                    continue
                
                # Update trusted domains
                for domain_entry in domains_list:
                    if isinstance(domain_entry, dict):
                        domain = domain_entry.get("domain")
                        ips = domain_entry.get("ips", [])
                        ttl = domain_entry.get("ttl", 300)
                    elif isinstance(domain_entry, str):
                        # If just a string, resolve it
                        domain = domain_entry
                        ips = self._resolve_domain(domain)
                        ttl = 300  # Default TTL
                    else:
                        continue
                    
                    if domain and ips:
                        self.update_domain(domain, ips, ttl, source="validated")
                
                logger.info(f"Successfully updated trusted domains from API: {url}")
            except Exception as e:
                logger.error(f"Error updating from API {api_config.get('url', 'unknown')}: {e}")
    
    def _extract_data_by_path(self, data, path):
        """Extract data from JSON by path string (e.g., 'result.domains')."""
        if isinstance(path, str):
            parts = path.split('.')
            current = data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current
        return data
    
    def _resolve_domain(self, domain: str) -> List[str]:
        """Resolve domain to IPs using system DNS."""
        ips = []
        try:
            for info in socket.getaddrinfo(domain, 0):
                ip = info[4][0]
                if ip not in ips:
                    ips.append(ip)
        except socket.gaierror:
            pass
        return ips