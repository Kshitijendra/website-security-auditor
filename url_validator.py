"""Target validation: only public http/https hosts; returns resolved IPs so the connection can be pinned."""
import ipaddress, socket
from urllib.parse import urlparse

class UnsafeTarget(Exception):
    pass

def is_public_ip(ip):
    a = ipaddress.ip_address(ip)
    return a.is_global and not a.is_multicast  # excludes loopback/private/link-local/reserved

def validate_url(url, resolver=socket.getaddrinfo):
    p = urlparse((url or "").strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeTarget("Only valid http/https URLs are accepted.")
    if p.username or p.password:
        raise UnsafeTarget("Credentials inside URLs are not allowed.")
    try:
        infos = resolver(p.hostname, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError):
        raise UnsafeTarget("DNS resolution failed for this host.")
    ips = sorted({i[4][0] for i in infos})
    if not ips or not all(is_public_ip(i) for i in ips):
        raise UnsafeTarget("Target resolves to a non-public address; blocked.")
    return p, ips
