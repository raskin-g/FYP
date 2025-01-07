import dns.message #for dns message formatting and parsing
import dns.query #to create dns quries
import dns.resolver #to resolve dns queries
import dns.rdatatype #dns record types
import dns.rcode #dns response codes
import socket #for creating udp socket
import threading #for multi-threading
import logging #logging
from datetime import datetime 
import time

#logging configuration
logging.basicConfig(
    filename='dns_server.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

class DNSServer:
    def __init__(self, host='0.0.0.0', port=53, upstream_server='8.8.8.8', blocklist_path='blocklist.txt'):
        self.host = host
        self.port = port
        self.upstream_server = upstream_server
        self.blocklist_path = blocklist_path
        self.blocked_domains = set()
        self.blocklist_lock = threading.Lock()  #adding thread-safe lock for blocklist updates
        self.load_blocklist()
        logging.info(f"Blocklist loaded with {len(self.blocked_domains)} domains")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind((self.host, self.port))
        
        #sarting the automatic blocklist update thread
        self.update_thread = threading.Thread(target=self.periodic_blocklist_update)
        self.update_thread.daemon = True
        self.update_thread.start()

    def load_blocklist(self):
        try:
            #using thread lock while updating blocklist
            with self.blocklist_lock:  
                self.blocked_domains.clear()
                with open(self.blocklist_path, 'r') as file:
                    for line in file:
                        domain = line.strip()
                        #checking and skiping empty line and hashtag
                        if domain and not domain.startswith('#'):  
                            self.blocked_domains.add(domain)
                
        except FileNotFoundError:
            logging.warning(f"Blocklist file not found at {self.blocklist_path}")
            self.blocked_domains.clear()
        except Exception as e:
            logging.error(f"Error loading blocklist: {str(e)}")

    def periodic_blocklist_update(self):
        while True:
            time.sleep(30)  #updating every 30 seconds
            self.load_blocklist()

    def is_domain_blocked(self, domain):
        with self.blocklist_lock:  #ussing lock when checking blocklist
            # checking if domain or any of its parent domains are in the blocklist
            parts = domain.split('.')
            for i in range(len(parts)):
                check_domain = '.'.join(parts[i:])
                if check_domain in self.blocked_domains:
                    return True
            return False

    def predict_suspicious(self, query):
        # TODO: Using the ML model  for prediction, The model will return False for benign query and True for malcious
        # For now every query is sent as benign except "netflix.com" for test purpose
        if query == "netflix.com":
            return True
        return False

    def handle_query(self, query_data, client_address):
        try:
            # retrieving incoming dns query
            query = dns.message.from_wire(query_data)
            
            # getting the requested domain
            question = query.question[0]
            domain = str(question.name).rstrip('.')
            
            log_entry = {
                'timestamp': datetime.now().isoformat(),
                'client': client_address[0],
                'domain': domain,
                'type': dns.rdatatype.to_text(question.rdtype),
                'blocked': False,
                'error': None
            }

            # Checking if domain is blocked
            if self.is_domain_blocked(domain):
                log_entry['blocked'] = True
                logging.info(f"BLOCKED - Client: {client_address[0]}, Domain: {domain}, Type: {log_entry['type']}")
                
                #creating own NXDOMAIN "error message" response 
                response = dns.message.make_response(query)
                response.set_rcode(dns.rcode.NXDOMAIN)
            else:
                #checking for potential suspicious query
                is_suspicious = self.predict_suspicious(domain)
                log_entry['predicted_suspicious'] = is_suspicious

                #foorwarding query to upstream server
                response = dns.query.udp(query, self.upstream_server, timeout=5)
                logging.info(f"ALLOWED - Client: {client_address[0]}, Domain: {domain}, Type: {log_entry['type']}, Suspicious: {is_suspicious}")

            #getting response back to client fromt he udp socket
            self.sock.sendto(response.to_wire(), client_address)

        except Exception as e:
            logging.error(f"Error processing query: {str(e)}")
            #sending error record type response if there is any error
            response = dns.message.make_response(query)
            response.set_rcode(dns.rcode.SERVFAIL)
            self.sock.sendto(response.to_wire(), client_address)

    def run(self):
        logging.info("DNS Server started on {}:{}".format(self.host, self.port))
        
        while True:
            try:
                query_data, client_address = self.sock.recvfrom(4096)
                #using one thread for one query for efficiency
                thread = threading.Thread(
                    target=self.handle_query,
                    args=(query_data, client_address)
                )
                thread.start()
            except Exception as e:
                logging.error(f"Error receiving data: {str(e)}")

def main():
    server = DNSServer(blocklist_path='blocklist.txt')
    server.run()

if __name__ == "__main__":
    main()
