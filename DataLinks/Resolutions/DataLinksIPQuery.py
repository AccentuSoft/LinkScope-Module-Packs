#!/usr/bin/env python3


class DataLinksIPQuery:
    name = "Get Threat Intel for IP Addresses"
    category = "Network Information"
    description = ("Get Threat Intelligence for the specified Domain or IP/IPv6 addresses. The risk level given for "
                   "each address is on a scale from 1 to 10, where 1 is completely benign 100% of the time, and 10 is "
                   "entirely malicious 100% of the time.")
    originTypes = {'IP Address', 'IPv6 Address', 'Domain'}
    resultTypes = {'Phrase', 'Network'}

    parameters = {'DataLinks API Key': {'description': 'Please enter your DataLinks API Key:',
                                         'type': 'String',
                                         'value': '',
                                         'global': True,
                                         'default': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import requests
        import contextlib

        headers = {'Content-Type': 'application/json',
                   'Authentication': f"Bearer {parameters['DataLinks API Key']}"}

        ips_dict = {
            entity[list(entity)[1]]: entity['uid'] for entity in entityJsonList
        }

        query_request = requests.post('https://datalinks.rest/query', headers=headers,
                                      json={"query": list(ips_dict.keys())})

        if query_request.status_code != 200:
            error_msg = f"Error occurred.\nDataLinks API returned status: {query_request.status_code}"
            with contextlib.suppress(Exception):
                error_msg_reason = query_request.json()['message']
                error_msg += f" {error_msg_reason}"
            return error_msg

        returnResults = []

        for net_addr, net_addr_info in query_request.json().items():
            tags = net_addr_info.get("tags")
            isp = net_addr_info.get("internet_services_provider")
            known_benign = net_addr_info.get("known_benign")
            known_scanner = net_addr_info.get("known_scanner")
            child_id = len(returnResults)
            netrange = net_addr_info.get('netrange')
            domain = net_addr_info.get('domain')
            entityJson = {'Phrase': f'{net_addr} Risk Rating: {net_addr_info["risk_level"]}',
                          'Tags': tags if tags is not None else "",
                          'Belongs to Internet Services Provider': str(isp) if isp is not None else "Unknown",
                          'Known to be Benign': str(known_benign) if known_benign is not None else "Unknown",
                          'Known Scanner': str(known_scanner) if known_scanner is not None else "Unknown",
                          'Entity Type': 'Phrase'}
            returnResults.append(
                [
                    entityJson,
                    {ips_dict[net_addr]: {'Resolution': 'Date Registered', 'Notes': ''}},
                ]
            )

            if netrange is not None and '/' in netrange:
                net, cidr = netrange.split('/', 1)
                returnResults.append(
                    [
                        {'IP Address': net,
                         'Range': cidr,
                         'Entity Type': 'Network'},
                        {child_id: {'Resolution': 'Netrange', 'Notes': ''}},
                    ]
                )
            elif domain is not None:
                returnResults.append(
                    [
                        {'Domain Name': domain,
                         'Entity Type': 'Domain'},
                        {child_id: {'Resolution': 'Domain', 'Notes': ''}},
                    ]
                )

        return returnResults
