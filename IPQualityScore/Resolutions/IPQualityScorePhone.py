#!/usr/bin/env python3


class IPQualityScorePhone:
    name = "IP Quality Score Phone"
    category = "Threats & Malware"
    description = "Find information about the location of a given IP Address or Validate an Email Address"
    originTypes = {'Phone Number'}
    resultTypes = {'Phone Number', 'Country', 'Company', 'City', 'Address', 'Company'}
    parameters = {'IPQualityScore Private Key': {'description': 'Enter your private key under your profile after '
                                                                'signing up on https://ipqualityscore.com. The limit '
                                                                'per month for free accounts is 5000 lookups.',
                                                 'type': 'String',
                                                 'value': '',
                                                 'global': True}}

    def resolution(self, entityJsonList, parameters):
        import requests

        key = parameters['IPQualityScore Private Key']

        def phone_number_api(phonenumber: str) -> dict:
            url = f'https://www.ipqualityscore.com/api/json/phone/{key}/{phonenumber}'
            request_result = requests.get(url, params={})
            return request_result.json()

        returnResults = []

        for entity in entityJsonList:
            primaryField = entity['Phone Number']
            lookup_result = phone_number_api(primaryField)
            if lookup_result.get('success', False) and lookup_result['message'] == "Phone is valid.":
                # Alter original input to add fields
                entity['Is Valid'] = str(lookup_result['valid'])
                entity['Line Type'] = str(lookup_result['line_type'])
                entity['Fraud Score'] = str(lookup_result['fraud_score'])
                entity['Carrier'] = str(lookup_result['carrier'])
                if lookup_result['associated_email_addresses']['status'] != 'Enterprise Plus or higher required.':
                    entity['Associated Emails'] = ', '.join(lookup_result['associated_email_addresses']['emails'])
                entity['Risky'] = str(lookup_result['risky'])
                entity['Active'] = str(lookup_result['active'])
                entity['Prepaid'] = str(lookup_result['prepaid']) if lookup_result['prepaid'] is not None else 'Unknown'
                if lookup_result['user_activity'] != 'Enterprise L4+ required.':
                    entity['User Activity'] = lookup_result['user_activity']
                entity['Prepaid'] = str(lookup_result['prepaid']) if lookup_result['prepaid'] is not None else 'Unknown'
                entity['Timezone'] = lookup_result['timezone']
                entity['Number in a Do Not Call list'] = str(lookup_result['do_not_call'])
                entity['Leaked'] = str(lookup_result['leaked'])
                entity['Spammer'] = str(lookup_result['spammer'])
                entity['Recent Abuse'] = str(lookup_result['recent_abuse'])
                entity['Active Status'] = lookup_result['active_status']
                entity['SMS Domain'] = lookup_result['sms_domain']
                entity['MNC'] = lookup_result['mnc']
                entity['MCC'] = lookup_result['mcc']
                entity['Name'] = lookup_result['name']
                entity['SMS Email'] = lookup_result['sms_email']

                resultsIndex = len(returnResults)
                returnResults.append([dict(entity),
                                      {'^@^^@^': {'Resolution': '',
                                                  'Notes': ''}}])
                returnResults.append([{'Country Name': lookup_result['country'],
                                       'Entity Type': 'Country'},
                                      {resultsIndex: {'Resolution': 'Phone Number Country'}}])
                returnResults.append([{'City Name': lookup_result['city'],
                                       'Entity Type': 'City'},
                                      {resultsIndex: {'Resolution': 'Phone Number City'}}])
                returnResults.append([{'Street Address': f"{primaryField} Street Unknown",
                                       'Locality': lookup_result['region'],
                                       'Postal Code': lookup_result['zip_code'],
                                       'Country': lookup_result['country'],
                                       'Entity Type': 'Address'},
                                      {resultsIndex: {'Resolution': 'Phone Number Address'}}])
                returnResults.append([{'Company Name': lookup_result['carrier'],
                                       'Entity Type': 'Company'},
                                      {resultsIndex: {'Resolution': 'Phone Number Carrier'}}])

        return returnResults
