#!/usr/bin/env python3


class CheckIfTORExit:
    name = "Is IP a TOR Exit"
    category = "Network Information"
    description = "Check if an IP or IPv6 Address is a TOR exit node."
    originTypes = {'IP Address', 'IPv6 Address'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {}

    def resolution(self, entityJsonList, parameters):
        import requests
        from datetime import datetime
        from pathlib import Path
        from bs4 import BeautifulSoup

        returnResults = []

        # Try to get latest TOR list
        datetime_today = str(datetime.today()).split(' ')[0]
        directory = Path(__file__).parent.resolve()

        current_list = directory / datetime_today

        if current_list.exists():
            with open(current_list, 'r') as tor_file:
                tor_exit_addresses = tor_file.read().splitlines()
        else:
            exit_lists_page = requests.get('https://metrics.torproject.org/collector/recent/exit-lists/')

            if exit_lists_page.status_code != 200:
                return "Failed getting TOR exit lists"
            soup = BeautifulSoup(exit_lists_page.content, 'lxml')

            latest_exit_list_url = soup.find_all('tbody')[0].find_all('a')[2]['href']

            tor_latest_exits = requests.get(latest_exit_list_url)

            if tor_latest_exits.status_code != 200:
                return "Failed getting latest TOR exits"

            tor_exit_addresses = [exit_address_line.split(' ')[0] for exit_address_line in
                                  tor_latest_exits.text.split('ExitAddress ')][1:]

            with open(current_list, 'w') as tor_file:
                tor_file.write('\n'.join(tor_exit_addresses))

        for entity in entityJsonList:
            if entity['Entity Type'] == 'IP Address':
                entity_address = entity['IP Address']
                if entity_address in tor_exit_addresses:
                    returnResults.append([{'IP Address': entity_address,
                                           'TOR Exit Node': 'True',
                                           'Entity Type': 'IP Address',
                                           'Canvas Banner': 'tor'},
                                          {'^^@@^^': {'Resolution': '', 'Notes': ''}}])
            else:
                entity_address = entity['IPv6 Address']
                if entity_address in tor_exit_addresses:
                    returnResults.append([{'IPv6 Address': entity_address,
                                           'TOR Exit Node': 'True',
                                           'Entity Type': 'IPv6 Address',
                                           'Canvas Banner': 'tor'},
                                          {'^^@@^^': {'Resolution': '', 'Notes': ''}}])

        return returnResults
