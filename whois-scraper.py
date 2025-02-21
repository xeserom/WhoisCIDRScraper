import requests
import csv
import asyncio
import utils
import os
from time import time

class IPv4Range:
    def __init__(self, start: str, end: str, owner: str):
        self.start = start
        self.end = end
        self.start_int = utils.ip_to_int(start)
        self.end_int = utils.ip_to_int(end)
        self.owner = owner

    def __repr__(self):
        return f'({self.start}, {self.end}, {self.owner})'

    def next_ip(self):
        return utils.int_to_ip(self.end_int + 1)

class IPv4Registry:
    def __init__(self):
        self.registry: set[IPv4Range] = set()

    def append(self, ip_range: IPv4Range):
        self.registry.add(ip_range)

    def find(self, ip: str):
        ip_int = utils.ip_to_int(ip)

        for ip_range in self.registry:
            if ip_int >= ip_range.start_int and ip_int <= ip_range.end_int:
                return ip_range

def make_option(name: str, options: bytes, range_finder):
    return { 
        name: (
            utils.resolve_domain(name), 
            options, 
            range_finder
        ) 
    }

WHOIS = {
    **make_option('whois.apnic.net', b'-V Md5.5.22 ', utils.find_range_in_whois_apnic),
    **make_option('whois.ripe.net', b'-V Md5.5.22 -B ', utils.find_range_in_whois_ripe),
    **make_option('whois.arin.net', b'n + ', utils.find_range_in_whois_arin),
    **make_option('whois.afrinic.net', b'-V Md5.5.22 -B ', utils.find_range_in_whois_afrinic),
    **make_option('whois.lacnic.net', b'', utils.find_range_in_whois_lacnic),
}

class Whois:
    def __init__(self):
        self.registry = Whois.load_registry()

    @staticmethod 
    def load_registry():
        if not os.path.exists('ipv4-address-space.csv'):
            with open('ipv4-address-space.csv', 'w') as f:
                r = requests.get('https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv').text
                f.write(r)

        with open('ipv4-address-space.csv', 'r') as f:
            reader = csv.reader(f, delimiter=',')

            registry: IPv4Registry = IPv4Registry()

            for row in list(reader)[1:]:
                prefix = row[0].split('/', 1)[0]
                whois_domain = row[3]
                
                if whois_domain:
                    if prefix.startswith('00'):
                        prefix = prefix.replace('00', '', 1)
                    elif prefix.startswith('0'):
                        prefix = prefix.replace('0', '', 1)

                    ip_range = IPv4Range(prefix + '.0.0.0', prefix + '.255.255.255', whois_domain)
                    registry.append(ip_range)

        return registry

    async def query(self, ip: str):
        answer = b''
        ip_range = self.registry.find(ip)
        
        if not ip_range:
            return

        whois_host, whois_options, range_finder = WHOIS[ip_range.owner]
        
        try:       
            async with asyncio.timeout(10):  
                reader, writer = await asyncio.open_connection(whois_host, 43)

            writer.write(whois_options + ip.encode() + b'\r\n')
            await writer.drain()

            while True:
                data = await reader.read(1024)

                if not data:
                    break
                else:
                    answer += data

            writer.close()
            await writer.wait_closed()
            utils.write_to_file('store/' + ip, answer)
        except:
            utils.append_to_file('failed-lookups', f'{ip}\n'.encode())
        finally:
            start_end = range_finder(answer)

            if start_end:
                return IPv4Range(*start_end, ip_range.owner)

class IPv4Stream:
    def __init__(self, ips: list[str], position: int = 0, chunk_size: int = 10):
        self.ips = ips
        self.position = position
        self.chunk_size = chunk_size
        
    def write(self, ip: str):
        self.ips.append(ip)

    def read(self):
        chunk_of_ips = self.ips[:self.chunk_size]
        self.ips = self.ips[self.chunk_size:]

        return chunk_of_ips
    
    def eos(self):
        return len(self.ips) < 1

def get_initial_ips():
    return [ip_range.start for ip_range in Whois.load_registry().registry]

def resume():    
    ip_registry = Whois.load_registry()
    whois_ips = os.listdir('./store')
    new_ip_registry = IPv4Registry()

    for whois_ip in whois_ips:
        with open(f'./store/{whois_ip}', 'rb') as f:
            whois_answer = f.read()

        ip_range = ip_registry.find(whois_ip)
        
        if not ip_range:
            continue

        start_end = WHOIS[ip_range.owner][2](whois_answer)

        if not start_end:
            #TODO check if whois answer was blocked
            continue

        new_ip_registry.append(IPv4Range(*start_end, ip_range.owner))

    return new_ip_registry

def find_missing_ips(ip_registry: IPv4Registry):
    ip_range_map = {}

    for ip_range in ip_registry.registry:
        ip_range_map[ip_range.start_int] = ip_range

    sorted_start_ips = list(ip_range_map.keys())
    sorted_start_ips.sort()

    sorted_ip_ranges: list[IPv4Range] = [
        ip_range_map[start_ip] for start_ip in sorted_start_ips
    ]

    missing_ips = [
        utils.int_to_ip(sorted_ip_ranges[i].end_int + 1)
        for i in range(len(sorted_ip_ranges) - 1)
        if sorted_ip_ranges[i].end_int + 1 != sorted_ip_ranges[i + 1].start_int
    ]

    saved_ips = os.listdir('store')
    #TODO filter bogon ips
    filtered_ips = [ip for ip in missing_ips if ip not in saved_ips]

    return filtered_ips

async def main():
    if not os.path.exists('store'):
        os.mkdir('store')

    ip_registry: IPv4Registry = resume()
    
    if not ip_registry.registry:
        ips_to_scan = get_initial_ips()
    else:
        ips_to_scan = find_missing_ips(ip_registry)

    whois = Whois()
    ip_stream = IPv4Stream(ips_to_scan)

    while ips_to_scan:
        while not ip_stream.eos():
            chunk = ip_stream.read()

            async with asyncio.TaskGroup() as tg:
                scraped_ranges = [tg.create_task(whois.query(ip)) for ip in chunk]
            
            for task in scraped_ranges:
                ip_range = task.result()

                if not ip_range:
                    continue
                
                print(ip_range)

                next_ip = ip_range.next_ip()
                
                if not ip_registry.find(next_ip):
                    ip_stream.write(next_ip)

                ip_registry.append(ip_range)

        ips_to_scan = find_missing_ips(ip_registry)

        for ip in ips_to_scan:
            ip_stream.write(ip)

if __name__ == '__main__':
    asyncio.run(main())