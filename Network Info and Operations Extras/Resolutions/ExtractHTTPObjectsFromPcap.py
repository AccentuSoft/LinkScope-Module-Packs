class ExtractHTTPObjectsFromPcap:
    name = "Extract HTTP Objects from pcap"
    category = "Network Information"
    description = "Extract any objects transferred over HTTP from a pcap file."
    originTypes = {'Document'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {}

    def resolution(self, entityJsonList, parameters):
        from scapy.all import rdpcap, TCP
        import magic
        import re
        import subprocess
        import contextlib
        from datetime import datetime
        from ipaddress import IPv6Address, IPv4Address, AddressValueError
        from pathlib import Path
        from uuid import uuid4
        from os import listdir

        returnResults = []

        for entity in entityJsonList:
            doc_path = Path(parameters['Project Files Directory']) / entity['File Path']
            if (not doc_path.exists()) or magic.from_file(doc_path, mime=True) != 'application/vnd.tcpdump.pcap':
                continue
            out_path_folder = str(uuid4())
            out_path = Path(parameters['Project Files Directory']) / out_path_folder
            subprocess.run(['tshark', '-q', '-Q', '-r', f'{doc_path}', '--export-objects', f'http,{out_path}'])

            pcap_docs = {}
            pcap_file = rdpcap(str(doc_path))
            sessions = pcap_file.sessions()
            for session in sessions:
                for packet in sessions[session]:
                    with contextlib.suppress(Exception):
                        if packet[TCP].dport == 80:
                            payload = bytes(packet[TCP].payload)
                            http_header_raw = payload[:payload.index(b"\r\n\r\n") + 2]
                            http_header_parsed = dict(
                                re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", http_header_raw.decode("utf8")))
                            try:
                                url_path = payload[payload.index(b"GET ") + 4:payload.index(b" HTTP/1.1")].decode(
                                    "utf8")
                            except Exception:
                                url_path = payload[payload.index(b"POST ") + 5: payload.index(b" HTTP/1.1")].decode(
                                    "utf8")
                            host = http_header_parsed["Host"]
                            time_arrived = packet.time
                            url_last_part = url_path.split('/')[-1]
                            if url_last_part in listdir(out_path):
                                pcap_docs[url_last_part] = (host, time_arrived)
            for doc, dest in pcap_docs.items():
                host = dest[0]
                time_arrived = dest[1]
                try:
                    cast_host = IPv4Address(host)
                    returnResults.append([{'IP Address': host,
                                           'Entity Type': 'IP Address'},
                                          {entity['uid']: {'Resolution': 'Sent Object over HTTP',
                                                           'Notes': ''}}])
                except AddressValueError:
                    try:
                        cast_host = IPv6Address(host)
                        returnResults.append([{'IPv6 Address': host,
                                               'Entity Type': 'IPv6 Address'},
                                              {entity['uid']: {'Resolution': 'Sent Object over HTTP',
                                                               'Notes': ''}}])
                    except AddressValueError:
                        returnResults.append([{'Domain Name': host,
                                               'Entity Type': 'Domain'},
                                              {entity['uid']: {'Resolution': 'Sent Object over HTTP',
                                                               'Notes': ''}}])
                returnResults.append([{'Document Name': doc,
                                       'File Path': str(Path(out_path_folder) / doc),
                                       'Date Created': f"{datetime.utcfromtimestamp(float(time_arrived)).isoformat()}"
                                                       f"+00:00",
                                       'Entity Type': 'Document'},
                                      {len(returnResults) - 1: {'Resolution': 'Sent From',
                                                                'Notes': ''}}])

        return returnResults
