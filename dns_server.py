import socket
import struct

# --- Configuration ---
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 5353
UPSTREAM_DNS = ("8.8.8.8", 53)

# Local DNS Records mapping domain strings to desired IPv4 responses
LOCAL_RECORDS = {
    "example.local": "192.168.1.100",
    "dev.local": "127.0.0.1",
}

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
    Parses an upstream DNS response packet to find and extract 
    the resolved IPv4 address for caching.
    """
    try:
        # 1. Skip the 12-byte header and decode the domain in the question section
        _, offset = decode_domain_name(response_data, 12)
        
        # 2. Skip past QTYPE (2 bytes) and QCLASS (2 bytes)
        offset += 4 
        
        # 3. Now we are at the Answer Section. 
        # Skip the name pointer/domain name component (usually 2 bytes like \xc0\x0c)
        offset += 2 
        
        # 4. Read Type, Class, TTL, and Data Length
        ans_type, ans_class, ans_ttl, ans_rdlength = struct.unpack('!HHIH', response_data[offset:offset+10])
        offset += 10
        
        # 5. If Type is 1 (A Record) and length is 4 bytes (IPv4), extract the raw IP bytes
        if ans_type == 1 and ans_rdlength == 4:
            raw_ip_bytes = response_data[offset:offset+4]
            # Convert raw bytes (e.g., \xc0\xa8\x01\x64) back to a string ("192.168.1.100")
            return socket.inet_ntoa(raw_ip_bytes)
            
    except Exception:
        return None # Return None if packet parsing fails (e.g., truncated packet)
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

def handle_client_query(data, client_address, server_socket):
    try:
        domain, offset = decode_domain_name(data, 12)
        qtype, qclass = struct.unpack('!2H', data[offset:offset+4])
        
        print(f"[Query] Request for '{domain}' (Type: {qtype}) from {client_address}")
        
        # ROUTING LOGIC 1: Permanent Local Records Match
        if domain in LOCAL_RECORDS and qtype == 1:
            print(f"  -> [Cache Hit] Resolving '{domain}' via LOCAL_RECORDS to {LOCAL_RECORDS[domain]}")
            response = build_local_response(data, domain, LOCAL_RECORDS[domain], qtype, qclass)
            server_socket.sendto(response, client_address)
        
        # ROUTING LOGIC 2: NEW! Dynamic In-Memory Cache Match
        elif domain in DYNAMIC_CACHE and qtype == 1:
            cached_ip = DYNAMIC_CACHE[domain]
            print(f"  -> [Dynamic Cache Hit] Resolving '{domain}' via MEMORY CACHE to {cached_ip}")
            response = build_local_response(data, domain, cached_ip, qtype, qclass)
            server_socket.sendto(response, client_address)
            
        # ROUTING LOGIC 3: Cache Miss (Forward & Learn)
        else:
            print(f"  -> [Cache Miss] Forwarding '{domain}' to upstream {UPSTREAM_DNS[0]}")
            proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            proxy_socket.settimeout(3.0)
            
            try:
                proxy_socket.sendto(data, UPSTREAM_DNS)
                upstream_response, _ = proxy_socket.recvfrom(512)
                
                # Send the answer back to the client immediately
                server_socket.sendto(upstream_response, client_address)
                
                # NEW: Try to extract the IP and save it to the cache for next time!
                if qtype == 1:
                    extracted_ip = extract_ip_from_response(upstream_response)
                    if extracted_ip:
                        DYNAMIC_CACHE[domain] = extracted_ip
                        print(f"  -> [Cache Update] Memorized '{domain}' = {extracted_ip}")
                        
            except socket.timeout:
                print(f"  !! [Timeout] Upstream {UPSTREAM_DNS} failed to respond.")
            finally:
                proxy_socket.close()
                
    except Exception as e:
        print(f"  !! [Error] Failed to process packet: {e}")
def main():
    # Setup UDP Listener socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    try:
        server_socket.bind((LISTEN_IP, LISTEN_PORT))
        print(f"[*] Custom DNS Server listening on {LISTEN_IP}:{LISTEN_PORT}...")
        
        while True:
            # DNS over UDP messages are traditionally restricted to a 512-byte payload maximum
            data, client_address = server_socket.recvfrom(512)
            handle_client_query(data, client_address, server_socket)
            
    except KeyboardInterrupt:
        print("\n[*] Shutting down DNS Server.")
    finally:
        server_socket.close()

if __name__ == "__main__":
    main()
