#!/usr/bin/env python3
"""
DNS packet analyzer for DNS Poisoning Detection System.
"""

import logging
import time
from collections import defaultdict
from datetime import datetime
from typing import Optional

logger = logging.getLogger("DNS_Monitor")

# Try to import required dependencies with helpful error messages
try:
    from scapy.all import DNS, DNSQR, DNSRR, IP, IPv6
    from scapy.layers.dns import dnstypes
except ImportError:
    logger.error("Error: 'scapy' package not installed. Please install it using: pip install scapy")
    raise ImportError("Missing 'scapy' package")

class DNSPacketAnalyzer:
    """Analyzes DNS packets for potential poisoning."""
    
    def __init__(self, config, trusted_domains):
        """Initialize DNS packet analyzer."""
        self.config = config
        self.trusted_domains = trusted_domains
        self.recent_alerts = defaultdict(list)  # domain -> list of alert timestamps
        self.packet_stats = {
            "total_packets": 0,
            "query_packets": 0,
            "response_packets": 0,
            "alerts": 0,
            "start_time": datetime.now().isoformat()
        }
    
    def analyze_packet(self, packet) -> Optional[dict]:
        """
        Analyze a DNS packet for potential poisoning.
        
        Returns:
            Alert dict if suspicious activity detected, None otherwise.
        """
        self.packet_stats["total_packets"] += 1
        
        # Check if packet has DNS layer
        if not packet.haslayer(DNS):
            return None
        
        # Process DNS query
        if packet.haslayer(DNSQR) and packet[DNS].qr == 0:
            self.packet_stats["query_packets"] += 1
            # Nothing to analyze for queries
            return None
        
        # Process DNS response
        if packet.haslayer(DNSRR) and packet[DNS].qr == 1:
            self.packet_stats["response_packets"] += 1
            return self._analyze_dns_response(packet)
        
        return None
    
    def _analyze_dns_response(self, packet) -> Optional[dict]:
        """Analyze DNS response packet for poisoning indicators."""
        try:
            # Extract response details
            if not packet.haslayer(DNSQR):
                return None
                
            try:
                domain = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            except (UnicodeDecodeError, AttributeError):
                logger.warning("Could not decode domain name in DNS response")
                return None
            
            # Skip analysis for whitelisted domains
            if domain in self.config.whitelisted_domains:
                return None
            
            # Collect resolved IPs
            resolved_ips = []
            
            # Get source IP
            if packet.haslayer(IP):
                src_ip = packet[IP].src
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
            else:
                src_ip = "unknown"
            
            # Skip if no answer records
            if packet[DNS].ancount == 0:
                return None
            
            dns_types = []
            ttls = []
            
            # Process all answer records
            try:
                for i in range(packet[DNS].ancount):
                    if isinstance(packet[DNS].an[i], DNSRR):
                        rr = packet[DNS].an[i]
                        record_type = dnstypes.get(rr.type, str(rr.type))
                        dns_types.append(record_type)
                        ttl = rr.ttl
                        ttls.append(ttl)
                        if record_type in ['A', 'AAAA']:
                            ip_addr = rr.rdata
                            if isinstance(ip_addr, bytes):
                                try:
                                    ip_addr = ip_addr.decode('utf-8')
                                except UnicodeDecodeError:
                                    ip_addr = str(ip_addr)
                            resolved_ips.append(str(ip_addr))
            except (IndexError, AttributeError) as e:
                logger.warning(f"Error processing DNS answer records: {e}")
                return None
            
            if not resolved_ips:
                return None
            
            # Use the minimum TTL for analysis
            ttl = min(ttls) if ttls else 0
            
            # Check if IPs are trusted and TTL is suspicious
            is_trusted, untrusted_ips = self.trusted_domains.are_ips_trusted(domain, resolved_ips)
            ttl_suspicious = self.trusted_domains.is_ttl_suspicious(domain, ttl)
            blacklisted_ips = [ip for ip in resolved_ips if ip in self.config.blacklisted_ips]
            
            # Determine if the response is suspicious
            is_suspicious = (not is_trusted) or ttl_suspicious or bool(blacklisted_ips)
            
            if not is_suspicious:
                self.trusted_domains.update_domain(domain, resolved_ips, ttl)
            
            if is_suspicious:
                current_time = time.time()
                domain_alerts = self.recent_alerts[domain]
                domain_alerts = [t for t in domain_alerts if current_time - t < 3600]  # last hour
                self.recent_alerts[domain] = domain_alerts
                if len(domain_alerts) >= self.config.alert_threshold:
                    return None
                self.recent_alerts[domain].append(current_time)
                self.packet_stats["alerts"] += 1
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "domain": domain,
                    "resolved_ips": resolved_ips,
                    "ttl": ttl,
                    "dns_types": dns_types,
                    "src_ip": src_ip,
                    "reason": []
                }
                if not is_trusted:
                    alert["reason"].append(f"Untrusted IPs: {', '.join(untrusted_ips)}")
                if ttl_suspicious:
                    trusted_ttl = self.trusted_domains.trusted_domains.get(domain, {}).get("ttl", "unknown")
                    alert["reason"].append(f"Suspicious TTL: {ttl} (trusted: {trusted_ttl})")
                if blacklisted_ips:
                    alert["reason"].append(f"Blacklisted IPs: {', '.join(blacklisted_ips)}")
                return alert
            
            return None
        except Exception as e:
            logger.error(f"Error analyzing DNS response: {e}")
            return None

    def get_stats(self) -> dict:
        """Return real-time DNS analysis statistics for the dashboard."""
        # Calculate human-readable uptime
        start_time = datetime.fromisoformat(self.packet_stats["start_time"])
        uptime_seconds = (datetime.now() - start_time).total_seconds()
        hours = int(uptime_seconds // 3600)
        minutes = int((uptime_seconds % 3600) // 60)
        seconds = int(uptime_seconds % 60)
        uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
        
        # Count trusted domains from the trusted_domains manager
        trusted_count = len(self.trusted_domains.trusted_domains) if self.trusted_domains else 0
        
        return {
            "total_packets": self.packet_stats.get("total_packets", 0),
            "alerts": self.packet_stats.get("alerts", 0),
            "uptime": uptime_str,
            "trusted_domains": trusted_count
            # You can extend this to include query_packets, response_packets, etc.
        }
