import argparse
import ipaddress
import json
from common import serve

def analyze(values):
    value=values.get('cidr','').strip()
    if len(value)>64: return {'error':'CIDR input is too long'}
    try: network=ipaddress.ip_network(value,strict=False)
    except ValueError as exc: return {'error':f'invalid CIDR: {exc}'}
    if network.num_addresses>2**32: host_first=host_last=None
    else:
        hosts=iter(network.hosts()); host_first=next(hosts,None); host_last=host_first
        if host_first is not None:
            for host_last in hosts: pass
    result={'input':value,'version':network.version,'network_address':str(network.network_address),'prefix_length':network.prefixlen,'netmask':str(network.netmask),'broadcast_address':str(network.broadcast_address) if network.version==4 else None,'total_addresses':network.num_addresses,'usable_host_count':max(0,network.num_addresses-2) if network.version==4 and network.prefixlen<31 else network.num_addresses,'first_usable':str(host_first) if host_first else None,'last_usable':str(host_last) if host_last else None}
    if network.num_addresses>2**32: result['note']='Host enumeration skipped for very large networks.'
    return result
def main():
    parser=argparse.ArgumentParser(description='Calculate CIDR details locally.')
    parser.add_argument('cidr',nargs='?'); parser.add_argument('--web',action='store_true'); parser.add_argument('--port',type=int,default=8091)
    args=parser.parse_args()
    if args.web: serve('CIDR Subnet Calculator',[('cidr','CIDR network','text','192.168.10.0/24')],analyze,args.port)
    elif args.cidr: print(json.dumps(analyze({'cidr':args.cidr}),indent=2))
    else: parser.print_help()
if __name__=='__main__': main()
