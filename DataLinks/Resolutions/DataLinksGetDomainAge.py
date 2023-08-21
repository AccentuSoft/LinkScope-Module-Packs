#!/usr/bin/env python3


class DataLinksGetDomainAge:
    name = "Get Domain Age"
    category = "Network Information"
    description = ("Get the latest date that the specified domain was updated at. This is most likely the date where "
                   "the current owner took control of the domain. Typically, domains are purchased for a year at a "
                   "time, so domains older than a year are much more reputable than domains that were created or "
                   "updated less than a year ago. The older a domain, the better.")
    originTypes = {'Domain', 'Website'}
    resultTypes = {'Phrase', 'Date'}

    parameters = {'DataLinks API Key': {'description': 'Please enter your DataLinks API Key:',
                                         'type': 'String',
                                         'value': '',
                                         'global': True,
                                         'default': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import requests
        import contextlib
        import tldextract

        headers = {'Content-Type': 'application/json',
                   'Authentication': f"Bearer {parameters['DataLinks API Key']}"}

        domains_dict = {}
        for entity in entityJsonList:
            primaryField = entity[list(entity)[1]]
            tld = tldextract.extract(primaryField)

            # Subdomains don't matter in this case.
            tld_string = f"{tld.domain}.{tld.suffix}"

            if tld_string not in domains_dict:
                domains_dict[tld_string] = []
            domains_dict[tld_string].append(entity['uid'])

        domain_ages = requests.post('https://datalinks.rest/domain_age', headers=headers,
                                    json={"domains": list(domains_dict.keys())})

        if domain_ages.status_code != 200:
            error_msg = f"Error occurred.\nDataLinks API returned status: {domain_ages.status_code}"
            with contextlib.suppress(Exception):
                error_msg_reason = domain_ages.json()['message']
                error_msg += f" {error_msg_reason}"
            return error_msg

        returnResults = []
        for domain_ages_dom, domain_ages_metrics in domain_ages.json().items():
            creation_date = domain_ages_metrics['Creation Date']
            if creation_date is not None:
                creation_entity_json = {'Date': creation_date, 'Entity Type': 'Date'}
            else:
                creation_entity_json = {'Phrase': 'Unknown Date', 'Entity Type': 'Phrase'}
            returnResults.extend(
                [
                    creation_entity_json,
                    {tld_uid: {'Resolution': 'Date Registered', 'Notes': ''}},
                ]
                for tld_uid in domains_dict[domain_ages_dom]
            )

            update_date = domain_ages_metrics['Latest Update']
            if update_date is not None:
                update_entity_json = {'Date': update_date, 'Entity Type': 'Date'}
            else:
                update_entity_json = {'Phrase': 'Unknown Date', 'Entity Type': 'Phrase'}
            returnResults.extend(
                [
                    update_entity_json,
                    {tld_uid: {'Resolution': 'Latest Update Date', 'Notes': ''}},
                ]
                for tld_uid in domains_dict[domain_ages_dom]
            )
        return returnResults
