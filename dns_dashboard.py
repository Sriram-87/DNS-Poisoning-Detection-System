#!/usr/bin/env python3
"""
Dashboard module for DNS Poisoning Detection System.
Provides a simple HTTP server that serves static files (e.g., index.html)
and exposes API endpoints for stats, controlling packet capture, updating configuration, and simulating attacks.
"""

import json
import logging
import os
import threading
from http.server import HTTPServer, SimpleHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

logger = logging.getLogger("DNS_Monitor")

class DashboardRequestHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self.get_stats_callback = kwargs.pop('get_stats_callback', None)
        self.simulate_callback = kwargs.pop('simulate_callback', None)
        self.config_callback = kwargs.pop('config_callback', None)
        self.start_callback = kwargs.pop('start_callback', None)
        self.stop_callback = kwargs.pop('stop_callback', None)
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed_path = urlparse(self.path)
        if parsed_path.path == '/api/stats':
            # Return live monitoring stats
            if self.get_stats_callback:
                stats = self.get_stats_callback()
                response = json.dumps(stats).encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(500, "No stats callback provided")
        elif parsed_path.path == '/api/start':
            if self.start_callback:
                self.start_callback()
                response = json.dumps({"status": "sniffer started"}).encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(500, "No start callback provided")
        elif parsed_path.path == '/api/stop':
            if self.stop_callback:
                self.stop_callback()
                response = json.dumps({"status": "sniffer stopped"}).encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(500, "No stop callback provided")
        elif parsed_path.path == '/api/config':
            # Update config; expect query parameter "interface"
            qs = parse_qs(parsed_path.query)
            new_interface = qs.get("interface", [None])[0]
            if new_interface is not None and self.config_callback:
                updated = self.config_callback(new_interface)
                response = json.dumps(updated).encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(400, "Missing 'interface' parameter")
        elif parsed_path.path == '/api/simulate':
            qs = parse_qs(parsed_path.query)
            domain = qs.get("domain", [None])[0]
            ip = qs.get("ip", [None])[0]
            attack_type = qs.get("type", [""])[0]  # optional
            if domain and ip and self.simulate_callback:
                result = self.simulate_callback(domain, ip)
                response = json.dumps(result).encode('utf-8')
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(response)))
                self.end_headers()
                self.wfile.write(response)
            else:
                self.send_error(400, "Missing 'domain' or 'ip' parameter")
        else:
            # Serve static files normally
            super().do_GET()

class DNSMonitorDashboard:
    def __init__(self, config, analyzer, sniffer, trusted_domains, simulator):
        self.config = config
        self.analyzer = analyzer
        self.sniffer = sniffer
        self.trusted_domains = trusted_domains
        self.simulator = simulator
        self.server = None
        self.thread = None

    def update_config(self, interface_value: str) -> dict:
        """Update the configuration with the new interface value."""
        self.config.interface = interface_value
        self.config.save_config()
        logger.info(f"Interface updated to: {interface_value}")
        return {"interface": self.config.interface}

    def start_dashboard(self):
        """Start the dashboard HTTP server in a separate thread."""
        try:
            port = self.config.dashboard_port
            # Set working directory to the folder containing index.html
            web_dir = os.path.dirname(os.path.abspath("index.html"))
            os.chdir(web_dir)
            
            def handler_factory(*args, **kwargs):
                return DashboardRequestHandler(
                    *args,
                    get_stats_callback=self.analyzer.get_stats,
                    simulate_callback=self.simulator.simulate_attack,
                    config_callback=self.update_config,
                    start_callback=self.sniffer.start_sniffing,
                    stop_callback=self.sniffer.stop_sniffing,
                    **kwargs
                )
            
            self.server = HTTPServer(("", port), handler_factory)
            logger.info(f"Dashboard server started on port {port}, serving files from {web_dir}")
            
            def serve():
                try:
                    self.server.serve_forever()
                except Exception as e:
                    logger.error(f"Dashboard server error: {e}")
            
            self.thread = threading.Thread(target=serve)
            self.thread.daemon = True
            self.thread.start()
        except Exception as e:
            logger.error(f"Failed to start dashboard: {e}")

    def stop_dashboard(self):
        """Stop the dashboard HTTP server."""
        if self.server:
            self.server.shutdown()
            self.thread.join(timeout=1.0)
            logger.info("Dashboard server stopped")
