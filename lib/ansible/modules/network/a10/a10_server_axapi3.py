#!/usr/bin/python
# -*- coding: utf-8 -*-

"""
Ansible module to manage A10 Networks slb server objects
(c) 2014, Mischa Peters <mpeters@a10networks.com>, 2016, Eric Chou <ericc@a10networks.com>, 2017, David Haupt <pdjopensource@gmail.com>

This file is part of Ansible

Ansible is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Ansible is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Ansible.  If not, see <http://www.gnu.org/licenses/>.
"""

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['preview'],
                    'supported_by': 'community'}


DOCUMENTATION = '''
---
module: a10_server_axapi3
version_added: 2.3
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices
description:
    - Manage SLB (Server Load Balancer) server objects on A10 Networks devices via aXAPIv3.
author: "Eric Chou (@ericchou) based on previous work by Mischa Peters (@mischapeters)"
extends_documentation_fragment: a10
options:
  server_name:
    description:
      - The SLB (Server Load Balancer) server name.
    required: true
    aliases: ['server']
  state:
    description:
      - Create or Remove SLB server. For create, we use the IP address and server
        name specified in the POST message. For delete operation, we use the server name in the request URI.
    required: false
    default: present
    choices: ['present', 'absent']
  server_ip:
    description:
      - The SLB (Server Load Balancer) server IPv4 address.
    required: true
    aliases: ['ip', 'address']
  server_status:
    description:
      - The SLB (Server Load Balancer) virtual server status.
    required: false
    default: enable
    aliases: ['action']
    choices: ['enable', 'disable']
  server_template:
    description:
      - Bind a real server template to the server. If a parameter is set individually on this server 
        and also is set in a server template bound to this server, the individual setting on this server is used instead 
        of the setting in the template.
    required: false
  server_ports:
    description:
      - A list of ports to create for the server. Each list item should be a dictionary which specifies the C(port:)
        and C(protocol:).
    required: false
    default: null
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']

'''

RETURN = '''
#
'''

EXAMPLES = '''
# Create a new server
- a10_server_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    server: test
    server_ip: 1.1.1.100
    validate_certs: false
    server_status: enable
    write_config: yes
    operation: create
    server_ports:
      - port-number: 8080
        protocol: tcp
        action: enable
      - port-number: 8443
        protocol: TCP

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

VALID_PORT_FIELDS = ['port-number', 'protocol', 'action', 'template-port']

def validate_ports(module, ports):
    for item in ports:
        for key in item:
            if key not in VALID_PORT_FIELDS:
                module.fail_json(msg="invalid port field (%s), must be one of: %s" % (key, ','.join(VALID_PORT_FIELDS)))

        # validate the port number is present and an integer
        if 'port-number' in item:
            try:
                item['port-number'] = int(item['port-number'])
            except:
                module.fail_json(msg="port-number entries in the port definitions must be integers")
        else:
            module.fail_json(msg="port definitions must define the port-number field")

        # validate the port protocol is present, no need to convert to the internal API integer value in v3
        if 'protocol' in item:
            protocol = item['protocol']
            if not protocol:
                module.fail_json(msg="invalid port protocol, must be one of: %s" % ','.join(AXAPI_PORT_PROTOCOLS))
            else:
                item['protocol'] = protocol
        else:
            module.fail_json(msg="port definitions must define the port protocol (%s)" % ','.join(AXAPI_PORT_PROTOCOLS))

        # 'status' is 'action' in AXAPIv3
        # no need to convert the status, a.k.a action, to the internal API integer value in v3
        # action is either enabled or disabled
        if 'action' in item:
            action = item['action']
            if action not in ['enable', 'disable']:
                module.fail_json(msg="server action must be enable or disable")
        else:
            item['action'] = 'enable'

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            server_name=dict(type='str', aliases=['name','server'], required=True),
            server_ip=dict(type='str', aliases=['ip', 'address'], required=True),
            server_template=dict(type='str', required=False),
            server_status=dict(type='str', default='enable', aliases=['action'], choices=['enable', 'disable']),
            server_ports=dict(type='list', aliases=['port'], default=[])
        )
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=False
    )

    host = module.params['host']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    write_config = module.params['write_config']
    slb_server = module.params['server_name']
    slb_server_ip = module.params['server_ip']
    slb_server_status = module.params['server_status']
    slb_server_ports = module.params['server_ports']
    slb_server_template = module.params['server_template']

    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    # validate the ports data structure
    validate_ports(module, slb_server_ports)


    json_post = {
        "server":
            {
                "name": slb_server,
                "host": slb_server_ip
            }
    }

    # add optional module parameters
    if slb_server_template:
        json_post['server']['template-server'] = slb_server_template
    if slb_server_ports:
        json_post['server']['port-list'] = slb_server_ports

    if slb_server_status:
        json_post['server']['action'] = slb_server_status

    slb_server_data = axapi_call_v3(module, axapi_base_url+'slb/server/' + slb_server, method='GET', body='', signature=signature)

    slb_server_exists = slb_server_data and slb_server_data.get('server') and slb_server_data.get('server').get('name')
    result = ''
    changed=False

    if state == 'absent' and not slb_server_exists:
        result = slb_server_data

    elif state == 'present' and slb_server_exists:
        result = slb_server_data

    elif state == 'absent' and slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/server/' + slb_server, method='DELETE', body='', signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to delete the server: %s" % result['response']['err']['msg'])
        changed=True

    elif state == 'present' and not slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/server/', method='POST', body=json.dumps(json_post), signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to create the server: %s" % result['response']['err']['msg'])
        changed=True

    # if the config has changed, save the config
    if changed:
        write_result = axapi_call_v3(module, axapi_base_url+'write/memory/', method='POST', body='', signature=signature)
        if axapi_failure(write_result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to save the configuration: %s" % write_result['response']['err']['msg'])

    # log out gracefully and exit
    axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
    module.exit_json(changed=changed, content=result)

if __name__ == '__main__':
    main()
