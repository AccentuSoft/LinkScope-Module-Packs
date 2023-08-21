#!/usr/bin/env python3


class DataLinksGetASNRanges:
    name = "Get ASN Ranges"
    category = "Network Information"
    description = ("Get all the network ranges for a given ASN. The Phrase input is stripped of non-numeric characters "
                   "and interpreted as the AS number to query.")
    originTypes = {'Phrase'}
    resultTypes = {'Network'}

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

        asns_dict = {}
        for entity in entityJsonList:
            primaryField = entity['Phrase']

            if primaryField not in asns_dict:
                asns_dict[primaryField] = []
            asns_dict[primaryField].append(entity['uid'])

        asns_ranges_req = requests.post('https://datalinks.rest/asn_ranges', headers=headers,
                                        json={"asns": list(asns_dict.keys())})

        if asns_ranges_req.status_code != 200:
            error_msg = f"Error occurred.\nDataLinks API returned status: {asns_ranges_req.status_code}"
            with contextlib.suppress(Exception):
                error_msg_reason = asns_ranges_req.json()['message']
                error_msg += f" {error_msg_reason}"
            return error_msg

        returnResults = []
        for asn, asn_ranges in asns_ranges_req.json().items():
            for asn_range in asn_ranges:
                net_p1, net_p2 = asn_range.split('/', 1)
                returnResults.extend(
                    [
                        {'IP Address': net_p1, 'Range': net_p2, 'Entity Type': 'Network'},
                        {asn_uid: {'Resolution': 'ASN Range', 'Notes': ''}},
                    ]
                    for asn_uid in asns_dict[asn]
                )

        return returnResults
