
#!/usr/bin/env python3

import ipaddress
import logging
import time

from collections import defaultdict, deque
from logging.handlers import RotatingFileHandler

import iptc

from scapy.all import sniff, IP, UDP, Raw


# --------------------------------------------------
# CONFIGURATION
# --------------------------------------------------

MAXTRYAUTH = 5
MAXTIMEAUTH = 5

SIP_PORT = 5060

WHITELISTPATH = "/etc/astfirewall/whitelist"
LOGPATH = "/var/log/asterisk/astfirewall.log"

INTERFACE = None

CHAIN_NAME = "astfirewall"


# --------------------------------------------------
# GLOBAL VARIABLES
# --------------------------------------------------

authentication_attempts = defaultdict(deque)
banned_ips = set()

logger = logging.getLogger(__name__)


# --------------------------------------------------
# LOGGING
# --------------------------------------------------

def setup_logging():

    logger.setLevel(logging.INFO)

    if logger.handlers:
        return

    handler = RotatingFileHandler(
        LOGPATH,
        maxBytes=5 * 1024 * 1024,
        backupCount=5
    )

    formatter = logging.Formatter(
        "%(asctime)s - %(levelname)s - %(message)s"
    )

    handler.setFormatter(formatter)
    logger.addHandler(handler)


# --------------------------------------------------
# WHITELIST
# --------------------------------------------------

def load_whitelist():

    whitelist = []

    try:
        with open(WHITELISTPATH, "r") as whitelist_file:

            for line_number, line in enumerate(
                whitelist_file, 1
            ):

                entry = line.strip()

                if not entry or entry.startswith("#"):
                    continue

                try:
                    network = ipaddress.ip_network(
                        entry,
                        strict=False
                    )

                    whitelist.append(network)

                except ValueError as error:
                    raise ValueError(
                        f"Invalid whitelist entry at line "
                        f"{line_number}: {entry}"
                    ) from error

    except FileNotFoundError:
        raise RuntimeError(
            f"Whitelist not found: {WHITELISTPATH}"
        )

    logger.info(
        "Whitelist loaded: %s entries",
        len(whitelist)
    )

    return whitelist


def whitelisted(ip, whitelist):

    address = ipaddress.ip_address(ip)

    return any(
        address in network
        for network in whitelist
    )


# --------------------------------------------------
# IPTABLES INITIALIZATION
# --------------------------------------------------

def setup_iptables():

    table = iptc.Table(iptc.Table.FILTER)

    if not table.is_chain(CHAIN_NAME):
        table.create_chain(CHAIN_NAME)

        logger.info(
            "Created chain %s",
            CHAIN_NAME
        )

    input_chain = iptc.Chain(table, "INPUT")

    # Avoid duplicate jump rules.

    for rule in input_chain.rules:

        if (
            rule.target is not None
            and rule.target.name == CHAIN_NAME
        ):

            logger.info(
                "Chain %s already connected to INPUT",
                CHAIN_NAME
            )

            return

    # Connect INPUT to the custom chain.

    rule = iptc.Rule()

    rule.target = iptc.Target(
        rule,
        CHAIN_NAME
    )

    input_chain.insert_rule(rule)

    table.commit()

    logger.info(
        "Chain %s connected to INPUT",
        CHAIN_NAME
    )


# --------------------------------------------------
# IP BAN
# --------------------------------------------------

def ban_ip(ip):

    try:

        address = ipaddress.ip_address(ip)

        if address.version != 4:
            logger.error(
                "IPv6 not supported by this configuration: %s",
                ip
            )
            return False

        table = iptc.Table(iptc.Table.FILTER)
        chain = iptc.Chain(table, CHAIN_NAME)

        # Check for an existing rule.

        for existing_rule in chain.rules:

            if (
                existing_rule.src in (ip, ip + "/32")
                and existing_rule.protocol == "udp"
                and existing_rule.target is not None
                and existing_rule.target.name == "DROP"
            ):

                if any(
                    match.name == "udp"
                    and match.dport == str(SIP_PORT)
                    for match in existing_rule.matches
                ):

                    logger.info(
                        "IP %s already banned",
                        ip
                    )

                    return True

        # Create DROP rule for SIP UDP traffic.

        rule = iptc.Rule()

        rule.src = ip + "/32"
        rule.protocol = "udp"

        udp_match = rule.create_match("udp")
        udp_match.dport = str(SIP_PORT)

        rule.target = iptc.Target(
            rule,
            "DROP"
        )

        chain.insert_rule(rule)

        table.commit()

        logger.warning(
            "BAN: IP %s blocked on UDP port %s",
            ip,
            SIP_PORT
        )

        return True

    except Exception:

        logger.exception(
            "Unable to ban IP %s",
            ip
        )

        return False


# --------------------------------------------------
# ATTEMPT CACHE
# --------------------------------------------------

def check_matches(ip):

    current_time = time.monotonic()

    attempts = authentication_attempts[ip]

    # Remove expired attempts.

    while attempts and (
        current_time - attempts[0] > MAXTIMEAUTH
    ):

        attempts.popleft()

    # Register current event.

    attempts.append(current_time)

    counter = len(attempts)

    logger.info(
        "IP %s: %s/%s attempts in %s seconds",
        ip,
        counter,
        MAXTRYAUTH,
        MAXTIMEAUTH
    )

    # Check thresholds.

    if counter >= MAXTRYAUTH:

        if ip not in banned_ips:

            if ban_ip(ip):

                banned_ips.add(ip)

                logger.warning(
                    "BAN applied: %s attempts in %s seconds - IP: %s",
                    counter,
                    MAXTIMEAUTH,
                    ip
                )


# --------------------------------------------------
# PACKET ANALYSIS
# --------------------------------------------------

def analyze_packet(packet, whitelist):

    if not packet.haslayer(IP):
        return

    if not packet.haslayer(UDP):
        return

    if not packet.haslayer(Raw):
        return

    # Only SIP server responses.

    if packet[UDP].sport != SIP_PORT:
        return

    payload = bytes(packet[Raw].load)

    status_line = payload.split(b"\r\n", 1)[0]

    # Conservative event detection:
    # SIP 403 Forbidden.
    #
    # A 401 response is not counted because it can
    # represent a legitimate authentication challenge.

    if not status_line.startswith(b"SIP/2.0 403"):
        return

    # Response destination is the client IP.

    ip_client = packet[IP].dst

    if whitelisted(ip_client, whitelist):

        logger.debug(
            "IP %s is whitelisted",
            ip_client
        )

        return

    logger.info(
        "SIP 403 detected for IP %s",
        ip_client
    )

    check_matches(ip_client)


# --------------------------------------------------
# SNIFFER
# --------------------------------------------------

def start_sniffer(whitelist):

    logger.info("Starting SIP sniffer")

    logger.info(
        "Monitoring UDP port %s",
        SIP_PORT
    )

    sniff(
        filter=f"udp and src port {SIP_PORT}",
        iface=INTERFACE,
        store=False,
        prn=lambda packet: analyze_packet(
            packet,
            whitelist
        )
    )


# --------------------------------------------------
# MAIN
# --------------------------------------------------

def main():

    setup_logging()

    logger.info("Starting AstFirewall")

    try:

        whitelist = load_whitelist()

        setup_iptables()

        start_sniffer(whitelist)

    except KeyboardInterrupt:

        logger.info("Stopping AstFirewall")

    except Exception:

        logger.exception(
            "AstFirewall execution error"
        )

        raise


if __name__ == "__main__":
    main()
