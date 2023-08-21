#!/usr/bin/env python3


class DataLinksGetIPASNRange:
    name = "Get ASN and Range for IP"
    category = "Network Information"
    description = "Get the ASN and the network that the given IP belongs to."
    originTypes = {'IP Address', 'IPv6 Address', 'Network'}
    resultTypes = {'Network', 'Phrase'}

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

        source_dict = {}
        for entity in entityJsonList:
            primaryField = entity[list(entity)[1]]

            if primaryField not in source_dict:
                source_dict[primaryField] = []
            source_dict[primaryField].append(entity['uid'])

        source_dict_req = requests.post('https://datalinks.rest/ip_asn_range', headers=headers,
                                        json={"ips": list(source_dict.keys())})

        if source_dict_req.status_code != 200:
            error_msg = f"Error occurred.\nDataLinks API returned status: {source_dict_req.status_code}"
            with contextlib.suppress(Exception):
                error_msg_reason = source_dict_req.json()['message']
                error_msg += f" {error_msg_reason}"
            return error_msg

        returnResults = []
        for source, asn_and_range in source_dict_req.json().items():
            asn = asn_and_range[0]
            net = asn_and_range[1]
            net_p1, net_p2 = net.split('/', 1)
            returnResults.extend(
                [
                    {'IP Address': net_p1, 'Range': net_p2, 'Entity Type': 'Network'},
                    {source_uid: {'Resolution': 'Source ASN', 'Notes': ''}},
                ]
                for source_uid in source_dict[source]
            )
            returnResults.extend(
                [
                    {'Phrase': f"AS {asn}", 'Entity Type': 'Phrase'},
                    {source_uid: {'Resolution': 'Source Network', 'Notes': ''}},
                ]
                for source_uid in source_dict[source]
            )

        return returnResults
