from http.server import BaseHTTPRequestHandler, HTTPServer
import time
import json
import random

class StreamingHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/predict':
            self.send_response(200)
            self.send_header('Content-type', 'application/json')
            self.end_headers()
            
            try:
                # Send 5 normal flows
                for _ in range(5):
                    flow = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S.000"),
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.50",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 80
                    }
                    self.wfile.write((json.dumps(flow) + '\n').encode('utf-8'))
                    self.wfile.flush()
                    time.sleep(0.5)
                    
                # Send 10 malicious flows
                for i in range(10):
                    flow = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S.000"),
                        "src_ip": "10.0.0.99",
                        "dst_ip": "192.168.1.5",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 445
                    }
                    if i == 9: # The 10th one has prediction
                        flow["prediction"] = "Scanning"
                    self.wfile.write((json.dumps(flow) + '\n').encode('utf-8'))
                    self.wfile.flush()
                    time.sleep(0.5)

                # Send 5 normal flows
                for _ in range(5):
                    flow = {
                        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S.000"),
                        "src_ip": "192.168.1.100",
                        "dst_ip": "10.0.0.50",
                        "src_port": random.randint(1024, 65535),
                        "dst_port": 80
                    }
                    self.wfile.write((json.dumps(flow) + '\n').encode('utf-8'))
                    self.wfile.flush()
                    time.sleep(0.5)
            except BrokenPipeError:
                print("Client disconnected")
            return

if __name__ == '__main__':
    print("Starting mock IDS server on port 8000...")
    HTTPServer(('', 8000), StreamingHandler).serve_forever()
