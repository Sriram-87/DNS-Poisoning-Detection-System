#!/usr/bin/env python3
"""
DNS Poisoning Detection System
A robust system to monitor DNS traffic, detect potential DNS poisoning attacks,
and alert administrators to suspicious activities.
"""

import argparse
import json
import logging
import os
import signal
import sys
import time
from datetime import datetime
import threading

# Local imports
from dns_config import DNSMonitorConfig
from dns_trusted_domains import TrustedDomainsManager
from dns_analyzer import DNSPacketAnalyzer
from dns_sniffer import DNSPacketSniffer
from dns_simulator import DNSPoisoningSimulator
from dns_dashboard import DNSMonitorDashboard

logger = logging.getLogger("DNS_Monitor")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("dns_monitor.log"),
        logging.StreamHandler(sys.stdout)
    ]
)

class DNSMonitor:
    """Main DNS Poisoning Detection System class."""
    
    def __init__(self, config_file: str = "config.json"):
        """Initialize DNS Monitor system."""
        self.config = DNSMonitorConfig(config_file)
        self.trusted_domains = TrustedDomainsManager(self.config)
        self.analyzer = DNSPacketAnalyzer(self.config, self.trusted_domains)
        self.sniffer = DNSPacketSniffer(self.config, self.analyzer)
        self.simulator = DNSPoisoningSimulator(self.config)
        # Do not auto-start the sniffer; it will be started by the dashboard API (/api/start)
        self.dashboard = DNSMonitorDashboard(self.config, self.analyzer, self.sniffer, self.trusted_domains, self.simulator)
        self.running = False
        self.update_thread = None
    
    def start(self):
        """Start the DNS monitoring system (without starting packet capture automatically)."""
        if self.running:
            logger.warning("DNS Monitor already running")
            return
        
        self.running = True
        # Start the dashboard server (serves index.html and API endpoints)
        self.dashboard.start_dashboard()
        
        # Start a thread to update trusted domains periodically
        self.update_thread = threading.Thread(target=self._run_updates)
        self.update_thread.daemon = True
        self.update_thread.start()
        
        logger.info("DNS Poisoning Detection System started")
    
    def stop(self):
        """Stop the DNS monitoring system."""
        if not self.running:
            logger.warning("DNS Monitor not running")
            return
        
        self.running = False
        # Stop packet capture if running
        self.sniffer.stop_sniffing()
        self.dashboard.stop_dashboard()
        if self.update_thread:
            self.update_thread.join(timeout=1.0)
        logger.info("DNS Poisoning Detection System stopped")
    
    def _run_updates(self):
        """Periodically update trusted domains from external APIs."""
        while self.running:
            try:
                self.trusted_domains.update_from_apis()
                for _ in range(self.config.update_interval // 10):
                    if not self.running:
                        break
                    time.sleep(10)
            except Exception as e:
                logger.error(f"Error in updater thread: {e}")
                time.sleep(60)
    
    def simulate_attack(self, target_domain: str, malicious_ip: str):
        """Simulate a DNS poisoning attack."""
        return self.simulator.simulate_attack(target_domain, malicious_ip)

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="DNS Poisoning Detection System")
    parser.add_argument("--config", type=str, default="config.json", help="Path to config file")
    parser.add_argument("--interface", type=str, help="Network interface to listen on")
    parser.add_argument("--simulate", action="store_true", help="Run in simulation mode from the command line")
    parser.add_argument("--domain", type=str, help="Domain to simulate attack on (with --simulate)")
    parser.add_argument("--ip", type=str, help="Malicious IP for simulation (with --simulate)")
    return parser.parse_args()

def main():
    """Main function."""
    args = parse_args()
    
    try:
        monitor = DNSMonitor(args.config)
        
        if args.interface:
            monitor.config.interface = args.interface
        
        # Command-line simulation mode (optional)
        if args.simulate:
            if not args.domain or not args.ip:
                print("Error: --domain and --ip are required with --simulate")
                sys.exit(1)
            result = monitor.simulate_attack(args.domain, args.ip)
            print(json.dumps(result, indent=2))
            return
        
        def signal_handler(sig, frame):
            print("\nShutting down DNS Monitor...")
            monitor.stop()
            sys.exit(0)
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        monitor.start()
        
        while True:
            time.sleep(1)
    
    except Exception as e:
        logger.critical(f"Fatal error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
