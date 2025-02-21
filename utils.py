from socket import inet_aton, inet_ntoa
from struct import unpack, pack
from socket import gethostbyname_ex

def resolve_domain(domain: str):
    _, _, ipaddrlist = gethostbyname_ex(domain)
    return ipaddrlist[0]

def ip_to_int(ip: str) -> int:
    return unpack("!L", inet_aton(ip))[0]

def int_to_ip(ip_int: int):
    return inet_ntoa(pack('!L', ip_int))

def write_to_file(filename: str, data: bytes):
    with open(filename, 'wb') as f:
        f.write(data)

def append_to_file(filename: str, data: bytes):
    with open(filename, 'ab') as f:
        f.write(data)

def block_to_range(block: str):
    ip, size = block.split('/', 1)
    ip_int = ip_to_int(ip) | ((1 << int(size)) - 1)
    return ip, int_to_ip(ip_int)

def find_range_in_whois_lacnic(whois_file: bytes):
    for line in whois_file.split(b'\n'):
        if line.startswith(b'inetnum:'):
            block = line[8:].strip().decode()
            ip_range = block_to_range(block)
            return ip_range
        
def find_range_in_whois_ripe(whois_file: bytes):
    for line in whois_file.split(b'\n'):
        if line.startswith(b'inetnum:'):
            contents = line[8:].strip()
            ip_start, ip_end = contents.split(b'-')
            return ip_start.strip().decode(), ip_end.strip().decode()

def find_range_in_whois_arin(whois_file: bytes):
    for line in whois_file.split(b'\n'):
        if line.startswith(b'NetRange:'):
            contents = line[9:].strip()
            ip_start, ip_end = contents.split(b'-')
            return ip_start.strip().decode(), ip_end.strip().decode()
        
def find_range_in_whois_afrinic(whois_file: bytes):
    return find_range_in_whois_ripe(whois_file)
        
def find_range_in_whois_apnic(whois_file: bytes):
    return find_range_in_whois_ripe(whois_file)