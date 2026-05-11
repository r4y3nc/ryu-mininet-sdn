from __future__ import print_function

import time

ZONE_WEB  = ["10.0.1.11", "10.0.1.12", "10.0.1.13"]
ZONE_DEV  = ["10.0.1.21", "10.0.1.22"]
ZONE_USER = ["10.0.1.31", "10.0.1.32"]

SESSION_TIMEOUT = 30
_sessions = {}


def get_zone(ip):
    if ip in ZONE_WEB:
        return "WEB"
    if ip in ZONE_DEV:
        return "DEV"
    if ip in ZONE_USER:
        return "USER"
    return None


def _register_session(src_ip, dst_ip):
    _sessions[(src_ip, dst_ip)] = time.time()


def _is_reply(src_ip, dst_ip):
    now = time.time()
    key = (dst_ip, src_ip)
    if key in _sessions:
        if now - _sessions[key] < SESSION_TIMEOUT:
            return True
        else:
            del _sessions[key]
    return False


def is_allowed(src_ip, dst_ip):
    src_zone = get_zone(src_ip)
    dst_zone = get_zone(dst_ip)

    if src_zone is None or dst_zone is None:
        return True

    if src_zone == dst_zone:
        return True

    if src_zone == "DEV" and dst_zone == "WEB":
        _register_session(src_ip, dst_ip)
        return True

    if src_zone == "WEB" and dst_zone == "DEV":
        return _is_reply(src_ip, dst_ip)

    return False


def is_allowed_to_vip(src_ip, tcp_pkt, icmp_pkt):
    if icmp_pkt:
        return False

    src_zone = get_zone(src_ip)
    if src_zone == "DEV" and tcp_pkt and tcp_pkt.dst_port == 22:
        return False

    return True