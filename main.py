"""Audit a simplified ordered firewall export for internet-exposed administration ports and fully shadowed rules."""
import argparse
import ipaddress
import json
from pathlib import Path

ADMIN_PORTS = {22,3389,5432,3306}

def audit(rules):
    parsed = []
    ids = set()
    for rule in rules:
        ident = rule['id']
        if not isinstance(ident,str) or ident in ids:
            raise ValueError('rule ids must be unique strings')
        ids.add(ident)
        network = ipaddress.ip_network(rule['source'],strict=False)
        ports = rule['ports']
        if not isinstance(ports,list) or not ports or any(type(p) is not int or not 1<=p<=65535 for p in ports):
            raise ValueError('ports must be a nonempty list of integers in 1..65535')
        if rule['action'] not in {'allow','deny'} or rule['protocol'] not in {'tcp','udp'}:
            raise ValueError('unsupported action or protocol')
        parsed.append((rule,network,set(ports)))
    findings = []
    for index,(rule,network,ports) in enumerate(parsed):
        if rule['action']=='allow' and network.prefixlen==0 and rule['protocol']=='tcp' and ports & ADMIN_PORTS:
            findings.append(dict(rule=rule['id'],kind='internet_admin_exposure',ports=sorted(ports & ADMIN_PORTS)))
        for previous,source,previous_ports in parsed[:index]:
            if network.version==source.version and network.subnet_of(source) and rule['protocol']==previous['protocol'] and ports <= previous_ports:
                findings.append(dict(rule=rule['id'],kind='shadowed',by=previous['id']))
                break
    return findings

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(audit(json.loads(args.input.read_text(encoding='utf-8'))),indent=2))
    except (OSError,ValueError,KeyError,TypeError) as exc:
        parser.exit(2,f'error: {exc}\n')

if __name__=='__main__': main()
