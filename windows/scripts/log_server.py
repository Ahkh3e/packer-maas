#!/usr/bin/env python3
"""
Simple HTTP log server for Windows build logging.
Receives POST requests with JSON log entries and organizes them by build ID.
"""

import json
import os
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime


class LogHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path == '/api/logs':
            try:
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)
                log_entry = json.loads(post_data.decode('utf-8'))
                
                # Create build-specific log directory
                build_id = log_entry.get('buildId', 'unknown')
                build_dir = f"build_logs/{build_id}"
                os.makedirs(build_dir, exist_ok=True)
                
                # Append to build log file
                log_line = f"[{log_entry.get('timestamp', datetime.now().isoformat())}] [{log_entry.get('level', 'INFO')}] {log_entry.get('message', '')}\n"
                with open(f"{build_dir}/setup.log", "a") as f:
                    f.write(log_line)
                
                # Also log to console for immediate feedback
                print(f"[{build_id[:8]}] {log_entry.get('level', 'INFO')}: {log_entry.get('message', '')}")
                
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(b'{"status": "ok"}')
                
            except Exception as e:
                print(f"Error processing log entry: {e}")
                self.send_response(500)
                self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress default HTTP server logging
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    
    # Create build_logs directory if it doesn't exist
    os.makedirs("build_logs", exist_ok=True)
    
    server = HTTPServer(('localhost', port), LogHandler)
    print(f"Log server started on http://localhost:{port}")
    print("Press Ctrl+C to stop")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down log server...")
        server.shutdown()


if __name__ == '__main__':
    main()