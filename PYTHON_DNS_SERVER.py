import dns.message
import dns.query
import dns.resolver
import dns.rdatatype
import dns.rcode
import socket
import threading
import logging
import logging.handlers
import time
import joblib
import re
import pandas as pd
import sqlite3
from http.server import SimpleHTTPRequestHandler, HTTPServer
from concurrent.futures import ThreadPoolExecutor
import tldextract
import os
import subprocess
from ipaddress import ip_address

# Custom logging setup
logger = logging.getLogger('DNSServer')
logger.setLevel(logging.INFO)
handler = logging.handlers.TimedRotatingFileHandler(
    filename='dns_server.log',
    when='midnight',
    interval=1,
    backupCount=7,
)
handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
logger.addHandler(handler)

# Configuration
BLOCKED_IP = '192.168.88.1'
HTTP_PORT = 80
DNS_PORT = 53

class BlockedPageHandler(SimpleHTTPRequestHandler):
    def do_GET(self):
        blocked_domain = self.path.lstrip('/')
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(f"""
        <!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Access Blocked</title>
</head>
<body style="font-family: 'Arial', sans-serif; margin: 0; padding: 0; background-color: #f8d7da; color: #721c24; display: flex; justify-content: center; align-items: center; height: 100vh; text-align: center;">
    <div style="background-color: #ffffff; border: 1px solid #f5c6cb; border-radius: 8px; padding: 30px; box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1); max-width: 500px; width: 90%;">
        <div style="background-color: #dc3545; color: #ffffff; padding: 10px; border-radius: 5px; font-size: 18px; margin-bottom: 20px;">Access Denied</div>
        <h1 style="font-size: 28px; margin-bottom: 20px; color: #721c24;">Security Alert</h1>
        <p style="font-size: 16px; margin-bottom: 20px; color: #495057;">Your request to {blocked_domain} has been blocked.</p>
        <p style="font-size: 16px; margin-bottom: 20px; color: #495057;">This domain has been identified as malicious by our security systems.</p>
        <p style="font-size: 14px; color: #6c757d;">
            If you believe this is a mistake, please contact the system administrator at 
            <a href="mailto:admin@example.com" style="color: #007bff; text-decoration: none;">admin@example.com</a>.
        </p>
    </div>
</body>
</html>
        """.encode('utf-8'))

def start_http_server():
    try:
        server = HTTPServer((BLOCKED_IP, HTTP_PORT), BlockedPageHandler)
        logger.info(f"HTTP server started on {BLOCKED_IP}:{HTTP_PORT}")
        server.serve_forever()
    except Exception as e:
        logger.error(f"HTTP server error: {str(e)}")

class DatabaseBlocklist:
    def __init__(self):
        self.blocked_domains = {}
        self.lock = threading.Lock()
        self.conn = sqlite3.connect('iocs.db', check_same_thread=False, timeout=10)
        self.refresh_cache()
        threading.Thread(target=self.auto_refresh, daemon=True).start()
        threading.Thread(target=self.clean_old_logs, daemon=True).start()

    def refresh_cache(self):
        with self.lock:
            try:
                c = self.conn.cursor()
                c.execute('''SELECT ioc_value, threat_type, malware_printable 
                             FROM iocs WHERE ioc_type = 'domain' AND blocked = 1''')
                self.blocked_domains = {
                    row[0].lower().rstrip('.'): (row[1], row[2]) for row in c.fetchall()
                }
                logger.info(f"Blocklist refreshed with {len(self.blocked_domains)} domains")
                self.sync_nftables_ips()
            except sqlite3.Error as e:
                logger.error(f"Database error: {str(e)}")

    def sync_nftables_ips(self):
        try:
            c = self.conn.cursor()
            c.execute('''SELECT ioc_value 
                         FROM iocs WHERE ioc_type = 'ip:port' AND blocked = 1''')
            db_ips = set(row[0] for row in c.fetchall())

            # Get current nftables IPs
            result = subprocess.run(['nft', 'list', 'set', 'inet', 'filter', 'blocklist'],
                                   capture_output=True, text=True)
            # Parse output like "elements = { 1.15.106.229, 3.125.40.198, ... }"
            current_ips = set()
            for line in result.stdout.splitlines():
                if 'elements = {' in line:
                    # Extract IPs from the elements line, removing braces and commas
                    ip_list = line[line.find('{')+1:line.find('}')].strip()
                    if ip_list:
                        current_ips.update(ip.strip() for ip in ip_list.split(',') if ip.strip())

            # Add new IPs
            for ip in db_ips - current_ips:
                try:
                    ip_address(ip)
                    subprocess.run(['nft', 'add', 'element', 'inet', 'filter', 'blocklist', f'{{ {ip} }}'],
                                  capture_output=True, text=True, check=True)
                except (ValueError, subprocess.CalledProcessError) as e:
                    logger.error(f"Failed to add IP {ip} to nftables: {str(e)}")
                    continue

            # Remove IPs no longer in database
            for ip in current_ips - db_ips:
                try:
                    ip_address(ip)
                    subprocess.run(['nft', 'delete', 'element', 'inet', 'filter', 'blocklist', f'{{ {ip} }}'],
                                  capture_output=True, text=True, check=True)
                except (ValueError, subprocess.CalledProcessError) as e:
                    logger.error(f"Failed to remove IP {ip} from nftables: {str(e)}")
                    continue

            # Fallback: if no IPs were updated and there are differences, flush and repopulate
            if (db_ips != current_ips) and not (db_ips.issubset(current_ips) and current_ips.issubset(db_ips)):
                try:
                    subprocess.run(['nft', 'flush', 'set', 'inet', 'filter', 'blocklist'],
                                  capture_output=True, text=True, check=True)
                    for ip in db_ips:
                        try:
                            ip_address(ip)
                            subprocess.run(['nft', 'add', 'element', 'inet', 'filter', 'blocklist', f'{{ {ip} }}'],
                                         capture_output=True, text=True, check=True)
                        except (ValueError, subprocess.CalledProcessError):
                            continue
                    logger.info("Flushed and repopulated nftables blocklist due to sync issues")
                except subprocess.CalledProcessError as e:
                    logger.error(f"Failed to flush/reload nftables blocklist: {str(e)}")

            logger.info("NFTables blocklist synced with database IPs")
        except Exception as e:
            logger.error(f"NFTables sync error: {str(e)}")

    def auto_refresh(self):
        while True:
            time.sleep(30)
            self.refresh_cache()

    def is_blocked(self, domain):
        clean_domain = domain.lower().rstrip('.')
        parts = clean_domain.split('.')
        with self.lock:
            for i in range(len(parts)):
                check_domain = '.'.join(parts[i:])
                if check_domain in self.blocked_domains:
                    threat_type, malware_printable = self.blocked_domains[check_domain]
                    return True, threat_type, malware_printable
        return False, None, None

    def log_access(self, domain, client_ip, record_type, blocked, threat_type, malware_printable, malicious_prediction):
        with self.lock:
            try:
                c = self.conn.cursor()
                c.execute('''INSERT INTO access_logs 
                             (timestamp, client_ip, domain, record_type, blocked, threat_type, malware_printable, malicious_prediction)
                             VALUES (datetime('now'), ?, ?, ?, ?, ?, ?, ?)''',
                         (client_ip, domain, record_type, int(blocked), threat_type, malware_printable, int(malicious_prediction)))
                self.conn.commit()
            except sqlite3.Error as e:
                logger.error(f"Logging error: {str(e)}")

    def clean_old_logs(self):
        while True:
            time.sleep(3600)
            with self.lock:
                try:
                    c = self.conn.cursor()
                    c.execute("DELETE FROM access_logs WHERE timestamp < datetime('now', '-1 day')")
                    self.conn.commit()
                    logger.info(f"Cleaned {c.rowcount} old log entries")
                except sqlite3.Error as e:
                    logger.error(f"Log cleaning error: {str(e)}")

class DNSServer:
    _STRANGE_CHAR_REGEX = re.compile(r'[a-zA-Z.]+')
    _DIGIT_REGEX = re.compile(r'\d+')

    def __init__(self, host='0.0.0.0', port=DNS_PORT, upstream_server='8.8.8.8'):
        self.host = host
        self.port = port
        self.upstream_server = upstream_server
        self.blocklist = DatabaseBlocklist()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            self.sock.bind((self.host, self.port))
        except Exception as e:
            logger.error(f"Failed to bind to {self.host}:{self.port}: {str(e)}")
            raise
        self.ml_model = joblib.load("DNS_MALICIOUS_PREDICTION_SVM.pkl")
        self.executor = ThreadPoolExecutor(max_workers=50)

    @classmethod
    def get_strange_characters(cls, domain):
        try:
            cleaned = cls._STRANGE_CHAR_REGEX.sub('', domain)
            if not cleaned:
                return 0
            digits = sum(c.isdigit() for c in cleaned)
            digits_adjusted = max(0, digits - 2) if digits > 2 else 0
            non_digits = cls._DIGIT_REGEX.sub('', cleaned)
            return len(non_digits) + digits_adjusted
        except Exception as e:
            logger.error(f"Strange characters error: {e}")
            return 0
        
    def check_spf_and_dmarc(self, domain):
        extracted = tldextract.extract(domain)
        root_domain = f"{extracted.domain}.{extracted.suffix}"
        spf_exists = False
        dmarc_exists = False
        try:
            answers = dns.resolver.resolve(root_domain, 'TXT')
            for record in answers:
                txt_data = b''.join(record.strings).decode('utf-8')
                if txt_data.startswith('v=spf1'):
                    spf_exists = True
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.error(f"SPF check error: {e}")
        try:
            dmarc_domain = f'_dmarc.{root_domain}'
            answers = dns.resolver.resolve(dmarc_domain, 'TXT')
            for record in answers:
                txt_data = b''.join(record.strings).decode('utf-8')
                if txt_data.startswith('v=DMARC1'):
                    dmarc_exists = True
                    break
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers):
            pass
        except Exception as e:
            logger.error(f"DMARC check error: {e}")
        return spf_exists, dmarc_exists

    def predict_suspicious(self, domain):
        spf_exists, dmarc_exists = self.check_spf_and_dmarc(domain)
        try:
            features = {
                'StrangeCharacters': self.get_strange_characters(domain),
                'NumericSequence': len(max(self._DIGIT_REGEX.findall(domain), key=len)) 
                    if self._DIGIT_REGEX.findall(domain) else 0,
                'NumericRatio': sum(c.isdigit() for c in domain) / len(domain) if domain else 0,
                'DomainLength': len(domain),
                'HasSPFInfo': spf_exists,
                'HasDmarcInfo': dmarc_exists
            }
            df = pd.DataFrame([features])
            probabilities = self.ml_model.predict_proba(df)[0]
            benign_probability = probabilities[0]
            malicious_probability = probabilities[1]
            if malicious_probability > 0.7:
                return True
            elif benign_probability > 0.6:
                return False
            else:
                return False
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            return False

    def handle_query(self, query_data, client_address):
        try:
            query = dns.message.from_wire(query_data)
        except Exception as e:
            logger.error(f"Invalid query from {client_address}: {str(e)}")
            response = dns.message.Message()
            response.set_rcode(dns.rcode.SERVFAIL)
            self.sock.sendto(response.to_wire(), client_address)
            return

        if not query.question:
            logger.error(f"Empty query from {client_address}")
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.FORMERR)
            self.sock.sendto(response.to_wire(), client_address)
            return

        question = query.question[0]
        domain = str(question.name).rstrip('.')
        record_type = dns.rdatatype.to_text(question.rdtype)

        blocked, threat_type, malware_printable = self.blocklist.is_blocked(domain)
        malicious_prediction = self.predict_suspicious(domain)

        self.blocklist.log_access(domain, client_address[0], record_type, blocked, threat_type, malware_printable, malicious_prediction)

        response = dns.message.make_response(query)
        if blocked:
            logger.info(f"BLOCKED - Client: {client_address[0]}, Domain: {domain}, Type: {record_type}")
            if question.rdtype == dns.rdatatype.A:
                response.answer.append(dns.rrset.from_text(
                    question.name, 300, dns.rdataclass.IN, dns.rdatatype.A, BLOCKED_IP
                ))
            else:
                response.set_rcode(dns.rcode.NXDOMAIN)
        else:
            logger.info(f"ALLOWED - Client: {client_address[0]}, Domain: {domain}, Type: {record_type}, Suspicious: {malicious_prediction}")
            try:
                response = dns.query.udp(query, self.upstream_server, timeout=5)
            except Exception as e:
                logger.error(f"Upstream query error: {str(e)}")
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.SERVFAIL)

        try:
            self.sock.sendto(response.to_wire(), client_address)
        except Exception as e:
            logger.error(f"Send response error: {str(e)}")

    def run(self):
        logger.info(f"DNS Server started on {self.host}:{self.port}")
        while True:
            try:
                query_data, client_address = self.sock.recvfrom(4096)
                self.executor.submit(self.handle_query, query_data, client_address)
            except Exception as e:
                logger.error(f"Receive error: {str(e)}")

def main():
    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()
    server = DNSServer()
    server.run()

if __name__ == "__main__":
    main()