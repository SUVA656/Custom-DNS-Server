import json
import time
import socket
import struct
import uuid
import logging
from logging.handlers import RotatingFileHandler

# =========================================================
# CONFIGURATION
# =========================================================

LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 5354

UPSTREAM_DNS = ("8.8.8.8", 53)

LOCAL_RECORDS = {}

BLOCKLIST_FILE = "blocklist.txt"
BLOCKLIST_DOMAINS = set()

# Structure:
# {
#   "domain": ("ip", expiration_timestamp)
# }
DYNAMIC_CACHE = {}

SECURITY_METRICS = {
    "blocked_domains": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "upstream_failures": 0,
    "local_resolutions": 0
}

# =========================================================
# LOGGING / AUDIT SYSTEM
# =========================================================

logger = logging.getLogger("DNSAudit")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    "dns_security_audit.log",
    maxBytes=10 * 1024 * 1024,  # 10MB
    backupCount=5
)

formatter = logging.Formatter('%(message)s')
handler.setFormatter(formatter)

logger.addHandler(handler)


def log_event(event_type,
              severity,
              domain=None,
              client_ip=None,
              action=None,
              outcome=None,
              details=None):

    log_entry = {
        "event_id": str(uuid.uuid4()),
        "timestamp": time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        "event_type": event_type,
        "severity": severity,
        "domain": domain,
        "client_ip": client_ip,
        "action": action,
        "outcome": outcome,
        "details": details
    }

    logger.info(json.dumps(log_entry))


# =========================================================
# CONFIG LOADER
# =========================================================

def load_configuration():
    global LISTEN_PORT
    global UPSTREAM_DNS
    global LOCAL_RECORDS
    global BLOCKLIST_FILE
    global BLOCKLIST_DOMAINS

    try:
        with open("config.json", "r") as f:
            config_data = json.load(f)

        LISTEN_PORT = config_data.get("listen_port", 5354)

        UPSTREAM_DNS = (
            config_data.get("upstream_dns_ip", "8.8.8.8"),
            config_data.get("upstream_dns_port", 53)
        )

        LOCAL_RECORDS = config_data.get("local_records", {})

        BLOCKLIST_FILE = config_data.get(
            "blocklist_file",
            "blocklist.txt"
        )

        BLOCKLIST_DOMAINS.clear()

        try:
            with open(BLOCKLIST_FILE, "r") as bf:
                for line in bf:
                    stripped = line.strip().lower()

                    if stripped and not stripped.startswith("#"):
                        BLOCKLIST_DOMAINS.add(stripped)

            print(
                f"[*] Loaded {len(BLOCKLIST_DOMAINS)} blocked domains."
            )

            log_event(
                event_type="CONFIG_LOAD",
                severity="INFO",
                action="LOAD_CONFIG",
                outcome="SUCCESS",
                details=f"Loaded {len(BLOCKLIST_DOMAINS)} blocklist domains"
            )

        except FileNotFoundError:

            print(f"[!] Blocklist file '{BLOCKLIST_FILE}' not found.")

            log_event(
                event_type="BLOCKLIST_MISSING",
                severity="WARNING",
                action="LOAD_BLOCKLIST",
                outcome="FAILED",
                details=f"Missing file: {BLOCKLIST_FILE}"
            )

    except Exception as e:

        print(f"[!] Failed to load config.json: {e}")

        log_event(
            event_type="CONFIG_LOAD_FAILED",
            severity="ERROR",
            action="LOAD_CONFIG",
            outcome="FAILED",
            details=str(e)
        )


# =========================================================
# DNS PARSER
# =========================================================

def decode_domain_name(data, offset):

    labels = []

    while True:

        length = data[offset]

        if length == 0:
            offset += 1
            break

        offset += 1

        label = data[offset:offset + length].decode('utf-8')

        labels.append(label)

        offset += length

    return ".".join(labels), offset


# =========================================================
# EXTRACT IP + TTL
# =========================================================

def extract_ip_from_response(response_data):

    try:

        _, offset = decode_domain_name(response_data, 12)

        offset += 4

        ancount = struct.unpack('!H', response_data[6:8])[0]

        for _ in range(ancount):

            if (response_data[offset] & 0xc0) == 0xc0:
                offset += 2
            else:
                _, offset = decode_domain_name(response_data, offset)

            ans_type, ans_class, ans_ttl, ans_rdlength = struct.unpack(
                '!HHIH',
                response_data[offset:offset + 10]
            )

            offset += 10

            if ans_type == 1 and ans_rdlength == 4:

                raw_ip_bytes = response_data[offset:offset + 4]

                return socket.inet_ntoa(raw_ip_bytes), ans_ttl

            offset += ans_rdlength

    except Exception as e:

        log_event(
            event_type="DNS_PARSE_ERROR",
            severity="ERROR",
            action="PARSE_RESPONSE",
            outcome="FAILED",
            details=str(e)
        )

    return None


# =========================================================
# BUILD DNS RESPONSE
# =========================================================

def build_local_response(query_data,
                         domain,
                         ip_address,
                         qtype,
                         qclass,
                         ttl=60):

    tx_id = query_data[:2]

    flags = struct.pack('!H', 0x8580)

    counts = struct.pack('!4H', 1, 1, 0, 0)

    header = tx_id + flags + counts

    _, question_end = decode_domain_name(query_data, 12)

    question_section = query_data[12:question_end + 4]

    pointer = struct.pack('!H', 0xc00c)

    ans_type = struct.pack('!H', qtype)

    ans_class = struct.pack('!H', qclass)

    ans_ttl = struct.pack('!I', ttl)

    ans_rdlength = struct.pack('!H', 4)

    ans_rdata = socket.inet_aton(ip_address)

    answer_section = (
        pointer +
        ans_type +
        ans_class +
        ans_ttl +
        ans_rdlength +
        ans_rdata
    )

    return header + question_section + answer_section


# =========================================================
# BUILD NXDOMAIN
# =========================================================

def build_nxdomain_response(query_data):

    tx_id = query_data[:2]

    flags = struct.pack('!H', 0x8183)

    counts = struct.pack('!4H', 1, 0, 0, 0)

    header = tx_id + flags + counts

    _, question_end = decode_domain_name(query_data, 12)

    question_section = query_data[12:question_end + 4]

    return header + question_section


# =========================================================
# BASIC THREAT DETECTION
# =========================================================

def suspicious_domain_heuristics(domain):

    domain_lower = domain.lower()

    if len(domain_lower) > 80:
        return "Excessively long domain"

    if domain_lower.count("-") > 10:
        return "Potential DGA domain"

    if domain_lower.endswith(".ru"):
        return "High-risk TLD"

    return None


# =========================================================
# MAIN ROUTING ENGINE
# =========================================================

def handle_client_query(data, client_address, server_socket):

    client_ip = client_address[0]

    try:

        domain, offset = decode_domain_name(data, 12)

        qtype, qclass = struct.unpack(
            '!2H',
            data[offset:offset + 4]
        )

        print(f"[Query] {domain} from {client_ip}")

        # =================================================
        # THREAT HEURISTICS
        # =================================================

        heuristic_result = suspicious_domain_heuristics(domain)

        if heuristic_result:

            log_event(
                event_type="SUSPICIOUS_DOMAIN",
                severity="WARNING",
                domain=domain,
                client_ip=client_ip,
                action="INSPECT",
                outcome="FLAGGED",
                details=heuristic_result
            )

        # =================================================
        # BLOCKLIST CHECK
        # =================================================

        if domain.lower() in BLOCKLIST_DOMAINS:

            SECURITY_METRICS["blocked_domains"] += 1

            print(f"[BLOCKED] {domain}")

            log_event(
                event_type="DNS_BLOCK",
                severity="CRITICAL",
                domain=domain,
                client_ip=client_ip,
                action="BLOCK",
                outcome="NXDOMAIN",
                details="Matched threat intelligence blocklist"
            )

            response = build_nxdomain_response(data)

            server_socket.sendto(response, client_address)

            return

        # =================================================
        # STATIC LOCAL RECORDS
        # =================================================

        elif domain in LOCAL_RECORDS and qtype == 1:

            SECURITY_METRICS["local_resolutions"] += 1

            local_ip = LOCAL_RECORDS[domain]

            print(f"[LOCAL] {domain} -> {local_ip}")

            log_event(
                event_type="LOCAL_RESOLUTION",
                severity="INFO",
                domain=domain,
                client_ip=client_ip,
                action="LOCAL_LOOKUP",
                outcome="SUCCESS",
                details=f"Resolved locally to {local_ip}"
            )

            response = build_local_response(
                data,
                domain,
                local_ip,
                qtype,
                qclass
            )

            server_socket.sendto(response, client_address)

            return

        # =================================================
        # DYNAMIC CACHE
        # =================================================

        elif domain in DYNAMIC_CACHE and qtype == 1:

            cached_ip, expiration_time = DYNAMIC_CACHE[domain]

            current_time = time.time()

            if current_time > expiration_time:

                print(f"[CACHE EXPIRED] {domain}")

                del DYNAMIC_CACHE[domain]

                log_event(
                    event_type="CACHE_EXPIRED",
                    severity="INFO",
                    domain=domain,
                    client_ip=client_ip,
                    action="CACHE_PURGE",
                    outcome="EXPIRED",
                    details="TTL expired"
                )

            else:

                SECURITY_METRICS["cache_hits"] += 1

                ttl_remaining = int(
                    expiration_time - current_time
                )

                print(
                    f"[CACHE HIT] {domain} -> {cached_ip}"
                )

                log_event(
                    event_type="CACHE_HIT",
                    severity="INFO",
                    domain=domain,
                    client_ip=client_ip,
                    action="CACHE_LOOKUP",
                    outcome="SUCCESS",
                    details=f"IP={cached_ip}, TTL={ttl_remaining}s"
                )

                response = build_local_response(
                    data,
                    domain,
                    cached_ip,
                    qtype,
                    qclass,
                    ttl=ttl_remaining
                )

                server_socket.sendto(response, client_address)

                return

        # =================================================
        # UPSTREAM FORWARDING
        # =================================================

        SECURITY_METRICS["cache_misses"] += 1

        print(f"[FORWARD] {domain} -> {UPSTREAM_DNS[0]}")

        log_event(
            event_type="CACHE_MISS",
            severity="INFO",
            domain=domain,
            client_ip=client_ip,
            action="FORWARD",
            outcome="UPSTREAM_QUERY",
            details=f"Forwarding to {UPSTREAM_DNS[0]}"
        )

        proxy_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        proxy_socket.settimeout(3.0)

        try:

            proxy_socket.sendto(data, UPSTREAM_DNS)

            upstream_response, _ = proxy_socket.recvfrom(512)

            server_socket.sendto(
                upstream_response,
                client_address
            )

            if qtype == 1:

                parsed_result = extract_ip_from_response(
                    upstream_response
                )

                if parsed_result:

                    extracted_ip, upstream_ttl = parsed_result

                    expire_timestamp = (
                        time.time() + upstream_ttl
                    )

                    DYNAMIC_CACHE[domain] = (
                        extracted_ip,
                        expire_timestamp
                    )

                    print(
                        f"[CACHE STORE] {domain} -> {extracted_ip}"
                    )

                    log_event(
                        event_type="CACHE_UPDATE",
                        severity="INFO",
                        domain=domain,
                        client_ip=client_ip,
                        action="CACHE_STORE",
                        outcome="SUCCESS",
                        details=f"Stored {extracted_ip} with TTL={upstream_ttl}"
                    )

        except socket.timeout:

            SECURITY_METRICS["upstream_failures"] += 1

            print("[TIMEOUT] Upstream DNS failed")

            log_event(
                event_type="UPSTREAM_TIMEOUT",
                severity="ERROR",
                domain=domain,
                client_ip=client_ip,
                action="FORWARD",
                outcome="TIMEOUT",
                details=f"Upstream {UPSTREAM_DNS[0]} did not respond"
            )

        finally:

            proxy_socket.close()

    except Exception as e:

        print(f"[ERROR] {e}")

        log_event(
            event_type="SERVER_EXCEPTION",
            severity="CRITICAL",
            client_ip=client_ip,
            action="PROCESS_QUERY",
            outcome="FAILED",
            details=str(e)
        )


# =========================================================
# SERVER MAIN LOOP
# =========================================================

def main():

    load_configuration()

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    try:

        server_socket.bind((LISTEN_IP, LISTEN_PORT))

        print(
            f"[*] DNS Server listening on "
            f"{LISTEN_IP}:{LISTEN_PORT}"
        )

        log_event(
            event_type="SERVER_START",
            severity="INFO",
            action="START_SERVER",
            outcome="SUCCESS",
            details=f"Listening on {LISTEN_IP}:{LISTEN_PORT}"
        )

        while True:

            data, client_address = server_socket.recvfrom(512)

            handle_client_query(
                data,
                client_address,
                server_socket
            )

    except KeyboardInterrupt:

        print("\n[*] Shutting down DNS Server.")

        log_event(
            event_type="SERVER_SHUTDOWN",
            severity="INFO",
            action="STOP_SERVER",
            outcome="SUCCESS",
            details="Manual shutdown"
        )

    finally:

        server_socket.close()


# =========================================================
# ENTRYPOINT
# =========================================================

if __name__ == "__main__":
    main()