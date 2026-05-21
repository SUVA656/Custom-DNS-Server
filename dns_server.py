import json
import time
import socket
import struct
import uuid
import logging
import threading

from concurrent.futures import ThreadPoolExecutor
from logging.handlers import RotatingFileHandler

# =========================================================
# CONFIGURATION
# =========================================================

LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

UPSTREAM_DNS = ("1.1.1.1", 53)

LOCAL_RECORDS = {}

BLOCKLIST_FILE = "blocklist.txt"
BLOCKLIST_DOMAINS = set()

# =========================================================
# CACHE
# =========================================================

# {
#     (domain, qtype): (ip, expiration_timestamp)
# }

DYNAMIC_CACHE = {}

CACHE_LOCK = threading.Lock()

SECURITY_METRICS = {
    "blocked_domains": 0,
    "cache_hits": 0,
    "cache_misses": 0,
    "upstream_failures": 0,
    "local_resolutions": 0
}

# =========================================================
# LOGGING
# =========================================================

logger = logging.getLogger("DNSAudit")
logger.setLevel(logging.INFO)

handler = RotatingFileHandler(
    "dns_security_audit.log",
    maxBytes=10 * 1024 * 1024,
    backupCount=5
)

formatter = logging.Formatter('%(message)s')

handler.setFormatter(formatter)

logger.addHandler(handler)

# =========================================================
# AUDIT LOGGING
# =========================================================

def log_event(event_type,
              severity,
              domain=None,
              client_ip=None,
              action=None,
              outcome=None,
              details=None):

    log_entry = {
        "event_id": str(uuid.uuid4()),
        "timestamp": time.strftime(
            '%Y-%m-%dT%H:%M:%SZ',
            time.gmtime()
        ),
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
# LOAD CONFIGURATION
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

        LISTEN_PORT = config_data.get(
            "listen_port",
            53
        )

        UPSTREAM_DNS = (
            config_data.get(
                "upstream_dns_ip",
                "1.1.1.1"
            ),
            config_data.get(
                "upstream_dns_port",
                53
            )
        )

        LOCAL_RECORDS = config_data.get(
            "local_records",
            {}
        )

        BLOCKLIST_FILE = config_data.get(
            "blocklist_file",
            "blocklist.txt"
        )

        BLOCKLIST_DOMAINS.clear()

        try:

            with open(BLOCKLIST_FILE, "r") as bf:

                for line in bf:

                    stripped = line.strip().lower()

                    if (
                        stripped
                        and not stripped.startswith("#")
                    ):
                        BLOCKLIST_DOMAINS.add(stripped)

            print(
                f"[*] Loaded "
                f"{len(BLOCKLIST_DOMAINS)} "
                f"blocked domains."
            )

            log_event(
                event_type="CONFIG_LOAD",
                severity="INFO",
                action="LOAD_CONFIG",
                outcome="SUCCESS",
                details=f"Loaded {len(BLOCKLIST_DOMAINS)} blocked domains"
            )

        except FileNotFoundError:

            print(
                f"[!] Blocklist file "
                f"'{BLOCKLIST_FILE}' not found."
            )

            log_event(
                event_type="BLOCKLIST_MISSING",
                severity="WARNING",
                action="LOAD_BLOCKLIST",
                outcome="FAILED",
                details=BLOCKLIST_FILE
            )

    except Exception as e:

        print(f"[CONFIG ERROR] {e}")

        log_event(
            event_type="CONFIG_LOAD_FAILED",
            severity="ERROR",
            action="LOAD_CONFIG",
            outcome="FAILED",
            details=str(e)
        )

# =========================================================
# DOMAIN DECODER WITH POINTER SUPPORT
# =========================================================

def decode_domain_name(data, offset):

    labels = []
    jumped = False
    original_offset = offset

    while True:

        length = data[offset]

        # Pointer
        if (length & 0xC0) == 0xC0:

            pointer = (
                ((length & 0x3F) << 8)
                | data[offset + 1]
            )

            if not jumped:
                original_offset = offset + 2

            offset = pointer
            jumped = True
            continue

        # End
        if length == 0:

            if not jumped:
                offset += 1

            break

        offset += 1

        label = data[
            offset:offset + length
        ].decode(
            'utf-8',
            errors='ignore'
        )

        labels.append(label)

        offset += length

    if jumped:
        return ".".join(labels), original_offset

    return ".".join(labels), offset

# =========================================================
# CACHE CLEANUP
# =========================================================

def cleanup_expired_cache():

    while True:

        try:

            current_time = time.time()

            with CACHE_LOCK:

                expired = []

                for key, (_, expiration) in DYNAMIC_CACHE.items():

                    if current_time > expiration:
                        expired.append(key)

                for key in expired:

                    domain, _ = key

                    del DYNAMIC_CACHE[key]

                    print(f"[CACHE EXPIRED] {domain}")

                    log_event(
                        event_type="CACHE_EXPIRED",
                        severity="INFO",
                        domain=domain,
                        action="CACHE_CLEANUP",
                        outcome="REMOVED",
                        details="TTL expired"
                    )

            time.sleep(30)

        except Exception as e:
            print(f"[CACHE CLEANUP ERROR] {e}")

# =========================================================
# RESPONSE PARSER
# =========================================================

def extract_ip_from_response(response_data):

    try:

        _, offset = decode_domain_name(
            response_data,
            12
        )

        offset += 4

        ancount = struct.unpack(
            '!H',
            response_data[6:8]
        )[0]

        for _ in range(ancount):

            _, offset = decode_domain_name(
                response_data,
                offset
            )

            ans_type, ans_class, ans_ttl, ans_rdlength = (
                struct.unpack(
                    '!HHIH',
                    response_data[offset:offset + 10]
                )
            )

            offset += 10

            if ans_type == 1 and ans_rdlength == 4:

                raw_ip = response_data[
                    offset:offset + 4
                ]

                return (
                    socket.inet_ntoa(raw_ip),
                    ans_ttl
                )

            offset += ans_rdlength

    except Exception as e:

        print(f"[PARSER ERROR] {e}")

        log_event(
            event_type="DNS_PARSE_ERROR",
            severity="ERROR",
            action="PARSE_RESPONSE",
            outcome="FAILED",
            details=str(e)
        )

    return None

# =========================================================
# LOCAL RESPONSE
# =========================================================

def build_local_response(query_data,
                         ip_address,
                         qtype,
                         qclass,
                         ttl=60):

    tx_id = query_data[:2]

    flags = struct.pack('!H', 0x8580)

    counts = struct.pack(
        '!4H',
        1,
        1,
        0,
        0
    )

    header = tx_id + flags + counts

    _, question_end = decode_domain_name(
        query_data,
        12
    )

    question_section = query_data[
        12:question_end + 4
    ]

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

    return (
        header +
        question_section +
        answer_section
    )

# =========================================================
# NXDOMAIN
# =========================================================

def build_nxdomain_response(query_data):

    tx_id = query_data[:2]

    flags = struct.pack('!H', 0x8183)

    counts = struct.pack(
        '!4H',
        1,
        0,
        0,
        0
    )

    header = tx_id + flags + counts

    _, question_end = decode_domain_name(
        query_data,
        12
    )

    question_section = query_data[
        12:question_end + 4
    ]

    return header + question_section

# =========================================================
# THREAT HEURISTICS
# =========================================================

def suspicious_domain_heuristics(domain):

    domain = domain.lower()

    if len(domain) > 80:
        return "Suspiciously long domain"

    if domain.count("-") > 10:
        return "Possible DGA domain"

    if domain.endswith(".ru"):
        return "High-risk TLD"

    return None

# =========================================================
# BLOCK CHECK
# =========================================================

def is_blocked(domain):

    domain = domain.lower()

    return any(
        domain == blocked or
        domain.endswith("." + blocked)
        for blocked in BLOCKLIST_DOMAINS
    )

# =========================================================
# QUERY HANDLER
# =========================================================

def handle_client_query(data,
                        client_address,
                        server_socket):

    client_ip = client_address[0]

    try:

        domain, offset = decode_domain_name(
            data,
            12
        )

        qtype, qclass = struct.unpack(
            '!2H',
            data[offset:offset + 4]
        )

        cache_key = (domain, qtype)

        print(
            f"[QUERY] "
            f"{domain} "
            f"from {client_ip}"
        )

        # =================================================
        # HEURISTICS
        # =================================================

        heuristic = suspicious_domain_heuristics(domain)

        if heuristic:

            log_event(
                event_type="SUSPICIOUS_DOMAIN",
                severity="WARNING",
                domain=domain,
                client_ip=client_ip,
                action="INSPECT",
                outcome="FLAGGED",
                details=heuristic
            )

        # =================================================
        # BLOCKLIST
        # =================================================

        if is_blocked(domain):

            SECURITY_METRICS["blocked_domains"] += 1

            print(f"[BLOCKED] {domain}")

            response = build_nxdomain_response(data)

            server_socket.sendto(
                response,
                client_address
            )

            log_event(
                event_type="DNS_BLOCK",
                severity="CRITICAL",
                domain=domain,
                client_ip=client_ip,
                action="BLOCK",
                outcome="NXDOMAIN",
                details="Threat intelligence match"
            )

            return

        # =================================================
        # LOCAL RECORDS
        # =================================================

        if (
            domain in LOCAL_RECORDS
            and qtype == 1
        ):

            SECURITY_METRICS["local_resolutions"] += 1

            local_ip = LOCAL_RECORDS[domain]

            print(
                f"[LOCAL] "
                f"{domain} -> {local_ip}"
            )

            response = build_local_response(
                data,
                local_ip,
                qtype,
                qclass
            )

            server_socket.sendto(
                response,
                client_address
            )

            return

        # =================================================
        # CACHE
        # =================================================

        with CACHE_LOCK:

            if cache_key in DYNAMIC_CACHE:

                cached_ip, expiration = (
                    DYNAMIC_CACHE[cache_key]
                )

                if time.time() < expiration:

                    SECURITY_METRICS["cache_hits"] += 1

                    ttl_remaining = int(
                        expiration - time.time()
                    )

                    print(
                        f"[CACHE HIT] {domain}"
                    )

                    response = build_local_response(
                        data,
                        cached_ip,
                        qtype,
                        qclass,
                        ttl_remaining
                    )

                    server_socket.sendto(
                        response,
                        client_address
                    )

                    return

                else:

                    del DYNAMIC_CACHE[cache_key]

        # =================================================
        # FORWARD
        # =================================================

        SECURITY_METRICS["cache_misses"] += 1

        print(f"[FORWARD] {domain}")

        proxy_socket = socket.socket(
            socket.AF_INET,
            socket.SOCK_DGRAM
        )

        proxy_socket.settimeout(5)

        try:

            proxy_socket.sendto(
                data,
                UPSTREAM_DNS
            )

            upstream_response, _ = (
                proxy_socket.recvfrom(512)
            )

            server_socket.sendto(
                upstream_response,
                client_address
            )

            if qtype == 1:

                parsed = extract_ip_from_response(
                    upstream_response
                )

                if parsed:

                    extracted_ip, upstream_ttl = parsed

                    with CACHE_LOCK:

                        DYNAMIC_CACHE[cache_key] = (
                            extracted_ip,
                            time.time() + upstream_ttl
                        )

                    print(
                        f"[CACHE STORE] "
                        f"{domain} -> {extracted_ip}"
                    )

                    log_event(
                        event_type="CACHE_STORE",
                        severity="INFO",
                        domain=domain,
                        client_ip=client_ip,
                        action="CACHE_UPDATE",
                        outcome="SUCCESS",
                        details=(
                            f"{extracted_ip} "
                            f"TTL={upstream_ttl}"
                        )
                    )

        except socket.timeout:

            SECURITY_METRICS["upstream_failures"] += 1

            print("[TIMEOUT] Upstream DNS timeout")

            log_event(
                event_type="UPSTREAM_TIMEOUT",
                severity="ERROR",
                domain=domain,
                client_ip=client_ip,
                action="FORWARD",
                outcome="TIMEOUT",
                details=UPSTREAM_DNS[0]
            )

        finally:

            proxy_socket.close()

    except Exception as e:

        print(f"[HANDLER ERROR] {e}")

        log_event(
            event_type="HANDLER_EXCEPTION",
            severity="CRITICAL",
            client_ip=client_ip,
            action="PROCESS_QUERY",
            outcome="FAILED",
            details=str(e)
        )

# =========================================================
# MAIN SERVER
# =========================================================

def main():

    load_configuration()

    cleanup_thread = threading.Thread(
        target=cleanup_expired_cache,
        daemon=True
    )

    cleanup_thread.start()

    executor = ThreadPoolExecutor(
        max_workers=100
    )

    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    try:

        server_socket.bind(
            (LISTEN_IP, LISTEN_PORT)
        )

        print(
            f"[*] DNS Server listening on "
            f"{LISTEN_IP}:{LISTEN_PORT}"
        )

        log_event(
            event_type="SERVER_START",
            severity="INFO",
            action="START_SERVER",
            outcome="SUCCESS",
            details=f"{LISTEN_IP}:{LISTEN_PORT}"
        )

        while True:

            try:

                data, client_address = (
                    server_socket.recvfrom(512)
                )

                executor.submit(
                    handle_client_query,
                    data,
                    client_address,
                    server_socket
                )

            except Exception as e:

                print(f"[MAIN LOOP ERROR] {e}")

    except KeyboardInterrupt:

        print("\n[*] DNS Server shutting down.")

    except Exception as e:

        print(f"[FATAL ERROR] {e}")

    finally:

        server_socket.close()

# =========================================================
# ENTRYPOINT
# =========================================================

if __name__ == "__main__":
    main()