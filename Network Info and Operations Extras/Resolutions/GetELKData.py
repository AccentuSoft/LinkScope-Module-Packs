class GetELKData:
    name = "Get ELK logs"
    category = "Network Information"
    description = "Get logs from an ELK stack running on the specified machines."
    originTypes = {'IP Address', 'IPv6 Address'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {'SSH Key file for root': {'description': 'Select the key file for ssh authentication as root to the '
                                                           'hosts specified as input.',
                                            'type': 'File',
                                            'value': ''},
                  'ElasticSearch Username': {'description': 'Please enter the username for the elasticsearch user to '
                                                            'authenticate as.',
                                             'type': 'String',
                                             'value': ''},
                  'ElasticSearch Password': {'description': 'Please enter the password for the elasticsearch user to '
                                                            'authenticate as.',
                                             'type': 'String',
                                             'value': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import paramiko
        import contextlib
        import json

        returnResults = []

        for entity in entityJsonList:
            if entity['Entity Type'] == 'IP Address':
                entity_address = entity['IP Address']
            else:
                entity_address = entity['IPv6 Address']
            try:
                pkey = paramiko.RSAKey.from_private_key_file(parameters['SSH Key file for root'])
                client = paramiko.SSHClient()
                policy = paramiko.AutoAddPolicy()
                client.set_missing_host_key_policy(policy)
                client.connect(entity_address, username='root', pkey=pkey)
            except Exception:
                return f'Failed to establish connection to server at: {entity_address}'

            base_command = f'curl -k -u "{parameters["ElasticSearch Username"]}:{parameters["ElasticSearch Password"]}"'

            cmd_stdin, cmd_stdout, cmd_stderr = client.exec_command(
                f'{base_command} https://localhost:9200/_cat/indices?format=json')
            stdout_json = json.loads(cmd_stdout.read())

            ips_connected = set()
            for index in stdout_json:
                index_name = index['index']
                index_stdin, index_stdout, index_stderr = client.exec_command(
                    f'{base_command} https://localhost:9200/{index_name}/_search')
                index_json = json.loads(index_stdout.read())
                for hit in index_json['hits']['hits']:
                    ips_connected.add(hit['_source']['source']['ip'])

            with contextlib.suppress(Exception):
                client.close()
            for result in ips_connected:
                if '.' in result:
                    returnResults.append([{'IP Address': result,
                                           'Entity Type': 'IP Address'},
                                          {entity['uid']: {'Resolution': 'IP Connected', 'Notes': ''}}])
                elif ':' in result:
                    returnResults.append([{'IPv6 Address': result,
                                           'Entity Type': 'IPv6 Address'},
                                          {entity['uid']: {'Resolution': 'IP Connected', 'Notes': ''}}])

        return returnResults

