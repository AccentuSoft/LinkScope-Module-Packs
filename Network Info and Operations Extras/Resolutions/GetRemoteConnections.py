class GetRemoteConnections:
    name = "Get Remote Connection Information"
    category = "Network Information"
    description = "Get what IP and IPv6 addresses connected to the hosts specified as input."
    originTypes = {'IP Address', 'IPv6 Address'}
    resultTypes = {'IP Address', 'IPv6 Address'}

    parameters = {'SSH Key file for root': {'description': 'Select the key file for ssh authentication as root to the '
                                                           'hosts specified as input.',
                                            'type': 'File',
                                            'value': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import paramiko
        import re
        import contextlib

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

            cmd_stdin, cmd_stdout, cmd_stderr = client.exec_command('last -i')
            txt_stdout_lines = cmd_stdout.read().decode('UTF-8').split('\n')

            cleaned_lines = []
            for line in txt_stdout_lines:
                if line == '':
                    break
                elif not line.startswith('reboot'):
                    cleaned_lines.append(line)
            remote_ips_from_last = [re.split(' +', line)[2] for line in cleaned_lines]
            remote_ips_connected = [line for line in remote_ips_from_last
                                    if line not in ['0.0.0.0', '::1', '127.0.0.1']]

            with contextlib.suppress(Exception):
                client.close()
            for result in remote_ips_connected:
                if '.' in result:
                    returnResults.append([{'IP Address': result,
                                           'Entity Type': 'IP Address'},
                                          {entity['uid']: {'Resolution': 'Remote Connection', 'Notes': ''}}])
                elif ':' in result:
                    returnResults.append([{'IPv6 Address': result,
                                           'Entity Type': 'IPv6 Address'},
                                          {entity['uid']: {'Resolution': 'Remote Connection', 'Notes': ''}}])

        return returnResults

