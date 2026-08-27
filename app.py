import argparse
import ipaddress
import json
from common import serve

def analyze(values):
    value = values.get('cidr','').strip()
    try: network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc: return {'error': f'Invalid CIDR: {exc}'}
    hosts = list(network.hosts()) if network.num_addresses <= 65536 else None
    result = {'input':value,'version':network.version,'network_address':str(network.network_address),'prefix_length':network.prefixlen,'netmask':str(network.netmask),'broadcast_address':str(network.broadcast_address) if network.version == 4 else None,'total_addresses':network.num_addresses,'usable_host_count':max(0, network.num_addresses - 2) if network.version == 4 and network.prefixlen < 31 else network.num_addresses,'first_usable':str(hosts[0]) if hosts else None,'last_usable':str(hosts[-1]) if hosts else None}
    if hosts is None: result['note'] = 'Host enumeration was skipped for networks larger than 65,536 addresses.'
    return result

def main():
    parser = argparse.ArgumentParser(description='Calculate CIDR details locally.')
    parser.add_argument('cidr', nargs='?'); parser.add_argument('--web', action='store_true'); parser.add_argument('--port', type=int, default=8091)
    args = parser.parse_args()
    if args.web: serve('CIDR Subnet Calculator', [('cidr','CIDR network','text','192.168.10.0/24')], analyze, args.port)
    elif args.cidr: print(json.dumps(analyze({'cidr':args.cidr}), indent=2))
    else: parser.print_help()

if __name__ == '__main__': main()
