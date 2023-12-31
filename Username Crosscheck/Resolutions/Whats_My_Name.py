#!/usr/bin/env python3

"""
Credits in wmn-data.json
"""


class Whats_My_Name:
    name = "Whats My Name"
    category = "Online Identity"
    description = "Find potentially connected social media accounts."
    originTypes = {'Phrase', 'Person', 'Social Media Handle'}
    resultTypes = {'Website'}
    parameters = {}

    def resolution(self, entityJsonList, parameters):
        from requests_futures.sessions import FuturesSession
        from concurrent.futures import as_completed
        from pathlib import Path
        import json
        import contextlib
        from playwright.sync_api import sync_playwright, TimeoutError

        import re
        from requests.exceptions import RequestException
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        playwrightPath = Path(parameters['Playwright Firefox'])

        headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64; rv:94.0) Gecko/20100101 Firefox/94.0',
        }

        futures = {}
        return_result = []

        directory = Path(__file__).parent.resolve()
        with open(directory / 'wmn-data.json', encoding='utf-8') as web_accounts_list:
            file = json.load(web_accounts_list)

        with sync_playwright() as p:
            browser = p.firefox.launch(executable_path=playwrightPath)
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080}
            )
            page = context.new_page()

            for entity in entityJsonList:
                uid = entity['uid']
                # Most services do not care about capitalization.
                # Some may redirect non-lowercase usernames, which could result in missed accounts.
                social_field = entity[list(entity)[1]].strip().lower()
                if entity['Entity Type'] == 'Social Media Handle' and social_field.startswith('@'):
                    social_field = social_field[1:]

                with FuturesSession(max_workers=15) as session:
                    for site in file['sites']:
                        if bad_chars := site.get('strip_bad_char'):
                            social_field = ''.join(char for char in social_field if char not in bad_chars)
                        original_uri = site['uri_check'].replace('{account}', social_field)
                        account_existence_code = site['e_code']
                        account_existence_string = site['e_string']
                        account_missing_string = site['m_string']
                        account_missing_code = site['m_code']
                        requires_javascript = site.get('requires_javascript', False)
                        site_headers = headers | site.get('headers', {})
                        if site.get('valid', True):
                            account_existence_string = re.escape(account_existence_string)
                            account_existence_string = re.compile(account_existence_string)
                            account_missing_string = re.escape(account_missing_string)
                            account_missing_string = re.compile(account_missing_string)
                            if requires_javascript:
                                for _ in range(3):
                                    with contextlib.suppress(TimeoutError):
                                        response = page.goto(original_uri, wait_until="networkidle", timeout=10000)
                                        status_code = response.status
                                        page_source = page.content()
                                        if status_code == account_existence_code and \
                                                account_existence_string != "" and \
                                                len(account_existence_string.findall(page_source)) > 0 and \
                                                (len(account_missing_string.findall(page_source)) == 0
                                                if account_missing_code == account_existence_code else True):
                                            return_result.append(
                                                [{'URL': original_uri,
                                                  'Entity Type': 'Website'},
                                                 {uid: {'Resolution': 'Whats My Name Account Match',
                                                        'Notes': ''}}])
                                        break
                            elif post_body := site.get('post_body'):
                                futures[session.post(original_uri, data=post_body, headers=site_headers,
                                                     timeout=10, allow_redirects=False)] = \
                                    (uid, account_existence_code, account_existence_string,
                                     account_missing_string, account_missing_code)
                            else:
                                futures[session.get(original_uri, headers=site_headers,
                                                    timeout=10, allow_redirects=False)] = \
                                    (uid, account_existence_code, account_existence_string,
                                     account_missing_string, account_missing_code)
                for future in as_completed(futures):
                    parent_uid = futures[future][0]
                    account_existence_code = futures[future][1]
                    account_existence_string = futures[future][2]
                    account_missing_string = futures[future][3]
                    account_missing_code = futures[future][4]
                    try:
                        first_response = future.result()
                    except RequestException:
                        continue
                    page_source = first_response.text
                    if first_response.status_code == account_existence_code and account_existence_string != "" and \
                            len(account_existence_string.findall(page_source)) > 0 and \
                            (len(account_missing_string.findall(page_source)) == 0
                            if account_missing_code == account_existence_code else True):
                        return_result.append([{'URL': first_response.url,
                                               'Entity Type': 'Website'},
                                              {parent_uid: {'Resolution': 'Whats My Name Account Match',
                                                            'Notes': ''}}])
            page.close()
            browser.close()
        return return_result


