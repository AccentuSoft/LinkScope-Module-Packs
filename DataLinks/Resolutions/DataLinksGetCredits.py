#!/usr/bin/env python3


class DataLinksGetCredits:
    name = "Get DataLinks Credits"
    category = "Network Information"
    description = ("Get the current amount of DataLinks credits available. Note that only select endpoints "
                   "cost credits to use. Credits are reset at the start of each month.")
    originTypes = {'*'}
    resultTypes = {'Phrase'}

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

        credits_req = requests.get('https://datalinks.rest/credits', headers=headers)

        if credits_req.status_code != 200:
            error_msg = f"Error occurred.\nDataLinks API returned status: {credits_req.status_code}"
            with contextlib.suppress(Exception):
                error_msg_reason = credits_req.json()['message']
                error_msg += f" {error_msg_reason}"
            return error_msg

        credits_amount = credits_req.json()['credits']

        return [
            [
                {
                    'Phrase': f"DataLinks Credits: {credits_amount}",
                    'Entity Type': 'Phrase',
                },
                {'@@@---@@@': {'Resolution': 'DataLinks Credits', 'Notes': ''}},
            ]
        ]
