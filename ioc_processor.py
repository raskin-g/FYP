import requests
import sqlite3
import os
from ipaddress import ip_address

API_URL = "https://threatfox-api.abuse.ch/api/v1/"
AUTH_KEY = "API-KEY" # Replace with your actual API key
DB_PATH = "iocs.db"

def fetch_iocs():
    headers = {"Auth-Key": AUTH_KEY}
    data = {"query": "get_iocs", "days": 1}
    response = requests.post(API_URL, headers=headers, json=data)
    print(f"API Response: {response.status_code} - {response.text}")
    return response.json() if response.status_code == 200 else None

def process_iocs():
    data = fetch_iocs()
    if not data or 'data' not in data:
        return

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS iocs
                 (id TEXT PRIMARY KEY,
                  ioc_value TEXT UNIQUE,
                  ioc_type TEXT,
                  threat_type TEXT,
                  malware_printable TEXT,
                  first_seen DATETIME,
                  last_seen DATETIME,
                  blocked BOOLEAN DEFAULT 0,
                  blocked_at DATETIME)''')
    
    for entry in data['data']:
        try:
            if entry['ioc_type'] not in ['domain', 'ip:port']:
                continue
                
            # Set ioc_value based on ioc_type
            if entry['ioc_type'] == 'domain':
                ioc_value = entry['ioc']
            elif entry['ioc_type'] == 'ip:port':
                ioc_value = entry['ioc'].split(':')[0]
                try:
                    ip_address(ioc_value)
                except ValueError:
                    print(f"Invalid IP address: {ioc_value}")
                    continue
            
            c.execute('''INSERT OR IGNORE INTO iocs 
                        (id, ioc_value, ioc_type, threat_type, 
                         malware_printable, first_seen, last_seen)
                        VALUES (?, ?, ?, ?, ?, ?, ?)''',
                     (entry['id'], ioc_value, entry['ioc_type'],
                      entry['threat_type'], entry['malware_printable'],
                      entry['first_seen'], entry['last_seen']))
            
            if c.rowcount > 0:
                c.execute('''UPDATE iocs SET 
                            blocked = 1, 
                            blocked_at = CURRENT_TIMESTAMP
                            WHERE id = ?''', (entry['id'],))
            
            conn.commit()
        except Exception as e:
            print(f"Error processing {entry['ioc']}: {str(e)}")
            conn.rollback()
    
    # Update nftables with all blocked IPs from the database
    update_nftables(conn)
    conn.close()

def update_nftables(conn):
    """Update nftables with all blocked IPs from the database."""
    c = conn.cursor()
    
    # Fetch all blocked IPs from the database
    c.execute("SELECT ioc_value FROM iocs WHERE ioc_type = 'ip:port' AND blocked = 1")
    blocked_ips = {row[0] for row in c.fetchall()}
    
    # Get current nftables set
    current_ips = set()
    try:
        with os.popen('nft list set inet filter blocklist') as f:
            current_ips = {line.strip() for line in f if line.strip() and ':' not in line}
    except Exception as e:
        print(f"Error reading nftables set: {str(e)}")
        return
    
    # Add new IPs to nftables
    for ip in blocked_ips - current_ips:
        try:
            ip_address(ip)  # Validate IP
            os.system(f"nft add element inet filter blocklist {{ {ip} }}")
            print(f"Added IP to nftables: {ip}")
        except ValueError:
            print(f"Invalid IP address: {ip}")
        except Exception as e:
            print(f"Error adding IP {ip} to nftables: {str(e)}")
    
    # Remove IPs that are no longer blocked
    for ip in current_ips - blocked_ips:
        try:
            os.system(f"nft delete element inet filter blocklist {{ {ip} }}")
            print(f"Removed IP from nftables: {ip}")
        except Exception as e:
            print(f"Error removing IP {ip} from nftables: {str(e)}")

if __name__ == "__main__":
    process_iocs()