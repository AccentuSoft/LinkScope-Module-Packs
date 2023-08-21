#!/usr/bin/env python3


class ExtractIPsFromNetflow:
    name = "Read IPs from Netflow file"
    category = "Network Information"
    description = "Read IP and IPv6 Addresses from a Netflow file."
    originTypes = {'Document'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {}

    def resolution(self, entityJsonList, parameters):
        from pathlib import Path
        import magic
        import subprocess
        import json

        returnResults = []

        for entity in entityJsonList:
            docPath = Path(parameters['Project Files Directory']) / entity['File Path']
            if (not docPath.exists()) or magic.from_file(docPath, mime=True) != 'application/octet-stream':
                continue

            try:
                json_data = subprocess.check_output(['nfdump', '-r', docPath, '-o', 'json'])
                netflow_data = json.loads(json_data)
            except subprocess.CalledProcessError:
                continue

            ipv4_addresses = set()
            ipv6_addresses = set()

            for flow in netflow_data:
                src4_ip = flow.get('src4_addr')
                src6_ip = flow.get('src6_addr')
                dst4_ip = flow.get('dst4_addr')
                dst6_ip = flow.get('dst6_addr')

                if src6_ip is not None:
                    ipv6_addresses.add(src6_ip)
                if dst6_ip is not None:
                    ipv6_addresses.add(dst6_ip)
                if src4_ip is not None:
                    ipv4_addresses.add(src4_ip)
                if dst4_ip is not None:
                    ipv4_addresses.add(dst4_ip)

            returnResults.extend(
                [{'IP Address': ip,
                  'Entity Type': 'IP Address'},
                 {entity['uid']: {'Resolution': 'Extracted IP Address',
                                  'Notes': ''}}
                 ]
                for ip in ipv4_addresses
            )
            returnResults.extend(
                [{'IPv6 Address': ip,
                  'Entity Type': 'IPv6 Address'},
                 {entity['uid']: {'Resolution': 'Extracted IPv6 Address',
                                  'Notes': ''}}
                 ]
                for ip in ipv6_addresses
            )

        return returnResults
