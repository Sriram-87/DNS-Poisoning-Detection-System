#!/usr/bin/env python3
"""
DNS packet sniffer for DNS Poisoning Detection System.
"""

import logging
import threading
from typing import List

logger = logging.getLogger("DNS_Monitor")

# Try to import required dependencies with helpful error messages
try:
    from scapy.all import sniff
except ImportError:
    logger.error("Error: 'scapy' package not installed. Please install it using: pip install scapy")
    raise ImportError("Missing 'scapy' package")

class DNSPacketSniffer:
    """Sniffs DNS packets from network interface."""
    
    def __init__(self, config, analyzer):
        """Initialize DNS packet sniffer."""
        self.config = config
        self.analyzer = analyzer
        self.running = False
        self.sniffer_thread = None
        self.alerts = []
        self.lock = threading.Lock()  # Add lock for thread safety
    
    def start_sniffing(self):
        """Start sniffing DNS packets in a separate thread."""
        if self.running:
            logger.warning("Sniffer already running")
            return
        
        self.running = True
        self.sniffer_thread = threading.Thread(target=self._sniff_packets)
        self.sniffer_thread.daemon = True
        self.sniffer_thread.start()
        logger.info(f"Started DNS packet sniffer on interface: {self.config.interface or 'default'}")
    
    def stop_sniffing(self):
        """Stop sniffing DNS packets."""
        self.running = False
        if self.sniffer_thread:
            self.sniffer_thread.join(timeout=1.0)
        logger.info("Stopped DNS packet sniffer")
    
    def _sniff_packets(self):
        """Sniff DNS packets and analyze them."""
        try:
            # Prepare filter
            bpf_filter = "udp port 53"
            
            # Prepare sniffing parameters
            kwargs = {
                "filter": bpf_filter,
                "prn": self._process_packet,
                "store": 0
            }
            
            if self.config.interface:
                kwargs["iface"] = self.config.interface
            
            # Start sniffing
            sniff(**kwargs)
        except Exception as e:
            logger.error(f"Error in packet sniffer: {e}")
            self.running = False
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        if not self.running:
            return
        
        alert = self.analyzer.analyze_packet(packet)
        if alert:
            with self.lock:  # Thread safety for alerts list
                self.alerts.append(alert)
                
                # Log alert
                reason = ", ".join(alert["reason"])
                logger.warning(f"DNS POISONING ALERT: Domain: {alert['domain']}, IPs: {alert['resolved_ips']}, Reason: {reason}")
                
                # Keep alerts list limited
                if len(self.alerts) > 100:
                    self.alerts = self.alerts[-100:]
    
    def get_alerts(self, count: int = 10) -> List[dict]:
        """Get recent alerts, most recent first."""
        with self.lock:  # Thread safety
            return sorted(self.alerts, key=lambda x: x["timestamp"], reverse=True)[:count]