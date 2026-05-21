import json
import time
import socket
import struct

# --- Configuration ---
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 5354
UPSTREAM_DNS = ("8.8.8.8", 53)

# Local DNS Records (Permanent)
LOCAL_RECORDS = {}

# NEW: Security threat intelligence storage
BLOCKLIST_FILE = "blocklist.txt"
BLOCKLIST_DOMAINS = set()

# NEW: In-memory dynamic cache for upstream answers
# Structure: {"domain": "ip_address"}
DYNAMIC_CACHE = {}

def load_configuration():
    global LISTEN_PORT, UPSTREAM_DNS, LOCAL_RECORDS, BLOCKLIST_FILE, BLOCKLIST_DOMAINS
    try:
        with open("config.json", "r") as f:
            config_data = json.load(f)
            
        LISTEN_PORT = config_data.get("listen_port", 5354)
        UPSTREAM_DNS = (
            config_data.get("upstream_dns_ip", "8.8.8.8"),
            config_data.get("upstream_dns_port", 53)
        )
        LOCAL_RECORDS = config_data.get("local_records", {})
        BLOCKLIST_FILE = config_data.get("blocklist_file", "blocklist.txt")
        
        # Load the blocklist domains from the specified text file
        BLOCKLIST_DOMAINS.clear()
        try:
            with open(BLOCKLIST_FILE, "r") as bf:
                for line in bf:
                    stripped = line.strip().lower()
                    if stripped and not stripped.startswith("#"):
                        BLOCKLIST_DOMAINS.add(stripped)
            print(f"[*] Configuration loaded. Loaded {len(BLOCKLIST_DOMAINS)} malicious domains into firewall memory.")
        except FileNotFoundError:
            print(f"[!] Warning: Blocklist file '{BLOCKLIST_FILE}' not found. No domains blocked.")
            
    except Exception as e:
        print(f"[!] Warning: Failed to load config.json ({e}). Using defaults.")

def decode_domain_name(data, offset):
    """
    Decodes a DNS byte-length label format into a standard domain string,
    returning the domain name and the new offset position.
    """
    labels = []
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        offset += 1
        label = data[offset:offset+length].decode('utf-8')
        labels.append(label)
        offset += length
    return ".".join(labels), offset

def extract_ip_from_response(response_data):
    """
    Parses an upstream DNS response packet, scanning through multiple answer
    records to find and extract the first valid Type-A IPv4 address and its TTL.
    """
    try:
        # 1. Move past header and decode domain in the Question section
        _, offset = decode_domain_name(response_data, 12)
        offset += 4  # Skip QTYPE (2B) and QCLASS (2B)
        
        # 2. Extract total Answer count from Header (bytes 6-7)
        ancount = struct.unpack('!H', response_data[6:8])[0]
        
        # 3. Loop through the Answer records to find an A-record (Type 1)
        for _ in range(ancount):
            # Check for compression pointer (0xc000) or raw label
            if (response_data[offset] & 0xc0) == 0xc0:
                offset += 2 # Skip compression pointer
            else:
                _, offset = decode_domain_name(response_data, offset)
                
            # Read Type, Class, TTL, and Data Length for this specific answer record
            ans_type, ans_class, ans_ttl, ans_rdlength = struct.unpack('!HHIH', response_data[offset:offset+10])
            offset += 10
            
            # If we found our A-record, extract the IP and return it!
            if ans_type == 1 and ans_rdlength == 4:
                raw_ip_bytes = response_data[offset:offset+4]
                return socket.inet_ntoa(raw_ip_bytes), ans_ttl
                
            # Otherwise, skip past this record's data block (like CNAME strings) and check the next one
            offset += ans_rdlength
            
    except Exception as e:
        # print(f"Parser debug exception: {e}") # Left here for debugging if needed
        return None
    return None

def build_local_response(query_data, domain, ip_address, qtype, qclass):
    """
    Constructs a valid raw DNS Type-A reply packet locally.
    Uses the \xc0\x0c compression pointer to reference the domain name.
    """
    # 1. Parse original Transaction ID
    tx_id = query_data[:2]
    
    # 2. Build Flags for Response: 
    # QR=1 (Response), Opcode=0000, AA=1 (Authoritative), TC=0, RD=1 (Desired)
    # RA=1 (Available), Z=000, RCODE=0000 (No Error) -> 0x8580
    flags = struct.pack('!H', 0x8580)
    
    # 3. Counts: 1 Question, 1 Answer, 0 Authority, 0 Additional
    counts = struct.pack('!4H', 1, 1, 0, 0)
    
    # Reconstruct header and append original question section
    header = tx_id + flags + counts
    
    # Locate where the question ends to extract the exact Question Section
    _, question_end = decode_domain_name(query_data, 12)
    question_section = query_data[12:question_end + 4] # domain + qtype (2B) + qclass (2B)
    
    # 4. Build Answer Section using Compression Pointer (\xc0\x0c)
    # \xc0\x0c points exactly to offset 12 (the start of the domain name in the Question)
    pointer = struct.pack('!H', 0xc00c)
    ans_type = struct.pack('!H', qtype)
    ans_class = struct.pack('!H', qclass)
    ans_ttl = struct.pack('!I', 60) # 60 seconds Time-to-Live
    ans_rdlength = struct.pack('!H', 4) # IPv4 address is always 4 bytes
    
    # Convert IP string (e.g., "192.168.1.100") to 4 raw bytes
    ans_rdata = socket.inet_aton(ip_address)
    
    answer_section = pointer + ans_type + ans_class + ans_ttl + ans_rdlength + ans_rdata
    
    return header + question_section + answer_section

def build_nxdomain_response(query_data):
    """
    Constructs a valid DNS reply packet with an NXDOMAIN (RCODE 3) error code,
    telling the client that the requested malicious domain does not exist.
    """
    tx_id = query_data[:2]
    
    # Flags: Response, Opcode 0, Authoritative=0, Recursion Desired=1, Recursion Available=1, RCODE=3 (NXDOMAIN)
    # Hex value: 0x8183
    flags = struct.pack('!H', 0x8183)
    
    # Counts: 1 Question, 0 Answers, 0 Authority, 0 Additional
    counts = struct.pack('!4H', 1, 0, 0, 0)
    
    header = tx_id + flags + counts
    
    # Replicate the original Question Section
    _, question_end = decode_domain_name(query_data, 12)
    question_section = query_data[12:question_end + 4]
    
    # NXDOMAIN responses carry no answer section, just the error flag!
    return header + question_section

def handle_client_query(data, client_address, server_socket):
    try:
        domain, offset = decode_domain_name(data, 12)
        qtype, qclass = struct.unpack('!2H', data[offset:offset+4])
        
        print(f"[Query] Request for '{domain}' (Type: {qtype}) from {client_address}")
        
        # ROUTING CRITERIA 1: Threat Intelligence Firewall
        if domain.lower() in BLOCKLIST_DOMAINS:
            print(f"  [SECURITY ALERT] Blocked request for malicious domain: '{domain}' from {client_address}")
            response = build_nxdomain_response(data)
            server_socket.sendto(response, client_address)
            return
            
        # ROUTING CRITERIA 2: Permanent Local Records Match
        elif domain in LOCAL_RECORDS and qtype == 1:
            print(f"  -> [Cache Hit] Resolving '{domain}' via LOCAL_RECORDS to {LOCAL_RECORDS[domain]}")
            response = build_local_response(data, domain, LOCAL_RECORDS[domain], qtype, qclass)
            server_socket.sendto(response, client_address)
        
        # ROUTING CRITERIA 3: Dynamic In-Memory Cache Match (With TTL Expiration Check)
        elif domain in DYNAMIC_CACHE and qtype == 1:
            cached_ip, expiration_time = DYNAMIC_CACHE[domain]
            current_time = time.time()
            
            # Check if the cache record has expired
            if current_time > expiration_time:
                print(f"  -> [Cache Stale] Record for '{domain}' expired. Purging memory cache.")
                del DYNAMIC_CACHE[domain]  # Clear out old data
                # Let it naturally fall through to the Cache Miss proxy logic below!
            else:
                ttl_remaining = int(expiration_time - current_time)
                print(f"  -> [Dynamic Cache Hit] Resolving '{domain}' (Valid for another {ttl_remaining}s) to {cached_ip}")
                response = build_local_response(data, domain, cached_ip, qtype, qclass)
                server_socket.sendto(response, client_address)
                return
                
        # ROUTING CRITERIA 4: Cache Miss (Forward, Learn, and Store TTL)
        # Note: Handled as a standard multi-conditional fall-through block
        if True:  
            print(f"  -> [Cache Miss] Forwarding '{domain}' to upstream {UPSTREAM_DNS[0]}")
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            proxy_socket.settimeout(3.0)
            
            try:
                proxy_socket.sendto(data, UPSTREAM_DNS)
                upstream_response, _ = proxy_socket.recvfrom(512)
                server_socket.sendto(upstream_response, client_address)
                
                if qtype == 1:
                    # Capture both the IP and the live TTL integer from the upstream response
                    parsed_result = extract_ip_from_response(upstream_response)
                    if parsed_result:
                        extracted_ip, upstream_ttl = parsed_result
                        
                        # Calculate absolute expiration time: current clock time + TTL seconds
                        expire_timestamp = time.time() + upstream_ttl
                        DYNAMIC_CACHE[domain] = (extracted_ip, expire_timestamp)
                        
                        print(f"  -> [Cache Update] Memorized '{domain}' = {extracted_ip} (TTL: {upstream_ttl}s)")
                        
            except socket.timeout:
                print(f"  !! [Timeout] Upstream {UPSTREAM_DNS} failed to respond.")
            finally:
                proxy_socket.close()
                
    except Exception as e:
        print(f"  !! [Error] Failed to process packet: {e}")

def main():
    # Setup UDP Listener socket
    load_configuration()
    
    # 2. Setup UDP Listener socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        print(f"[*] Custom DNS Server listening on {LISTEN_IP}:{LISTEN_PORT}...")
        
        while True:
            data, client_address = server_socket.recvfrom(512)
            handle_client_query(data, client_address, server_socket)
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down DNS Server.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
