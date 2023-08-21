class RunCommandOnTarget:
    name = "Run Command"
    category = "Network Operations"
    description = "Run a command on the default root shell of the target machine."
    originTypes = {'IP Address', 'IPv6 Address'}
    resultTypes = {'Phrase'}

    parameters = {'SSH Key file for root': {'description': 'Select the key file for ssh authentication as root to the '
                                                           'hosts specified as input.',
                                            'type': 'File',
                                            'value': ''},
                  'Command to run': {'description': 'Please enter the command to run on the machines as root.',
                                     'type': 'String',
                                     'value': ''}
                  }

    def resolution(self, entityJsonList, parameters):
        import paramiko
        import contextlib
        from time import time_ns

        returnResults = []

        command = parameters['Command to run']

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

            timestamp = str(time_ns())
            cmd_stdin, cmd_stdout, cmd_stderr = client.exec_command(
                f"{command}")
            txt_stdout = cmd_stdout.read().decode('UTF-8')
            txt_stderr = cmd_stderr.read().decode('UTF-8')

            with contextlib.suppress(Exception):
                client.close()
            returnResults.append([{'Phrase': f"{command} StdOut @{timestamp}",
                                   'Entity Type': 'Phrase',
                                   'Notes': txt_stdout},
                                  {entity['uid']: {'Resolution': 'Command StdOut', 'Notes': ''}}])
            returnResults.append([{'Phrase': f"{command} StdErr @{timestamp}",
                                   'Entity Type': 'Phrase',
                                   'Notes': txt_stderr},
                                  {entity['uid']: {'Resolution': 'Command StdErr', 'Notes': ''}}])

        return returnResults
