#!/usr/bin/env python3


class ReadPCAP:
    name = "Read IPs from Pcap file"
    category = "Network Information"
    description = "Read IP and IPv6 Addresses from a PCAP file."
    originTypes = {'Document'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {}

    def resolution(self, entityJsonList, parameters):
        from pathlib import Path
        from scapy.all import IP, IPv6, PcapReader
        import magic

        returnResults = []

        for entity in entityJsonList:
            docPath = Path(parameters['Project Files Directory']) / entity['File Path']
            if (not docPath.exists()) or magic.from_file(docPath, mime=True) not in ('application/vnd.tcpdump.pcap',
                                                                                     'application/octet-stream'):
                continue

            IP.payload_guess = []
            IPv6.payload_guess = []

            ipv4s = set()
            ipv6s = set()
            try:
                for p in PcapReader(str(docPath)):
                    if IP in p:
                        ipv4s.add(p[IP].src)
                        ipv4s.add(p[IP].dst)
                    elif IPv6 in p:
                        ipv6s.add(p[IPv6].src)
                        ipv6s.add(p[IPv6].dst)
    
                returnResults.extend(
                    [{'IP Address': ip,
                      'Entity Type': 'IP Address'},
                     {entity['uid']: {'Resolution': 'Extracted IP Address',
                                      'Notes': ''}}
                     ]
                    for ip in ipv4s
                )
                returnResults.extend(
                    [{'IPv6 Address': ip,
                      'Entity Type': 'IPv6 Address'},
                     {entity['uid']: {'Resolution': 'Extracted IPv6 Address',
                                      'Notes': ''}}
                     ]
                    for ip in ipv6s
                )
                
            except Exception:
                continue

        return returnResults


