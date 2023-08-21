#!/usr/bin/env python3


class DataLinksGetASNBlocklist:
    name = "Get ASN Blocklist"
    category = "Network Information"
    description = ("Get an IPSet-style blocklist script for the given ASN. The Phrase input is stripped of non-numeric "
                   "characters and interpreted as the AS number to query. The blocklist can be activated by running "
                   "the script like so:\nbash ./script block\nThe ASN can be unblocked by running the script with "
                   "'unblock' as the first argument, like so:\nbash ./script unblock\n")
    originTypes = {'Phrase'}
    resultTypes = {'Document'}

    parameters = {'DataLinks API Key': {'description': 'Please enter your DataLinks API Key:',
                                         'type': 'String',
                                         'value': '',
                                         'global': True,
                                         'default': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import requests
        import contextlib
        from pathlib import Path

        headers = {'Content-Type': 'application/json',
                   'Authentication': f"Bearer {parameters['DataLinks API Key']}"}

        returnResults = []

        for entity in entityJsonList:
            primaryField = entity['Phrase']

            blocklist_req = requests.post('https://datalinks.rest/block_list', headers=headers,
                                          json={"asn": primaryField})

            if blocklist_req.status_code != 200:
                error_msg = f"Error occurred.\nDataLinks API returned status: {blocklist_req.status_code}"
                with contextlib.suppress(Exception):
                    error_msg_reason = blocklist_req.json()['message']
                    error_msg += f" {error_msg_reason}"
                return error_msg

            block_script = blocklist_req.json()['block_script']
            docName = f"{primaryField}_blockscript.sh"
            docBasePath = Path(parameters['Project Files Directory'])
            docFullPath = docBasePath / docName
            x = 2
            while docFullPath.exists():
                docName = f"{primaryField}_blockscript_{x}.sh"
                docFullPath = docBasePath / docName
                x += 1

            with open(docFullPath, 'w') as bsf:
                bsf.write(block_script)

            returnResults.append(
                [
                    {'Document Name': docName, 'File Path': str(docFullPath.name), 'Entity Type': 'Document'},
                    {entity['uid']: {'Resolution': 'ASN Block Script', 'Notes': ''}},
                ]
            )

        return returnResults
