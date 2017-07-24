#!/usr/bin/python
# -*- coding: utf-8 -*-

""" Ansible module to manage A10 Networks slb service group objects 
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
module: a10_template_server_axapi3
version_added: 3.X
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' health monitors.
description:
    - Manage SLB (Server Load Balancing) server template objects on A10 Networks devices via aXAPIv3.
author: "David Haupt 2017 (pdjopensource@gmail.com), Eric Chou (@ericchou) 2016, Mischa Peters (@mischapeters) 2014"
notes:
    - Requires A10 Networks aXAPI 3.0
    - For now only http health monitors are implemented.
extends_documentation_fragment: a10
options:
  template_server:
    description:
      - The SLB (Server Load Balancing) template server name
    required: true
    default: null
    aliases: ['name', 'template']
  state:
    description:
      - The template state
    default: present
    choices: ['present','absent']
  health_check:
    description:
      - Enables health monitoring of ports that use this template. Specify the name of a configured health monitor. If you omit this command or you enter it without the monitor-name, the default ICMP health monitor is used: an ICMP ping (echo request) is sent every 30 seconds. If the ping fails 2 times consecutively, the ACOS device sets the server state to DOWN..
    required: false
  health_check_disable:
    description:
      - Disables health monitoring of servers that use this template.
    required: false
    choices: ['true','false']
  weight:
    description:
      - Assigns an administrative weight to the server, for weighted load balancing. The numbered parameter is the administrative weight assigned to the server.
    required: false
  validate_certs:
    description:
      - If C(no), SSL certificates will not be validated. This should only be used
        on personally controlled devices using self-signed certificates.
    required: false
    default: 'yes'
    choices: ['yes', 'no']

'''

EXAMPLES = '''
# Create a new server template
- a10_template_port_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    template_server: my_template_server
    state: present
    health_check: my_hm_http

'''

RETURN = '''
content:
  description: The full info regarding the server template
  returned: success
  type: string
  sample: "template server"

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure, axapi_enabled_disabled
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present','absent']),
            template_server=dict(type='str', aliases=['name', 'template'], required=True),
            health_check=dict(type='str', aliases=['monitor']),
            health_check_disable=dict(type='str'),
            weight=dict(type='int')
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

    template_server = module.params['template_server']
    template_monitor = module.params['health_check']
    template_monitor_disable = module.params['health_check_disable']
    template_weight = module.params['weight']

    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    # validate the server data list structure
    #validate_servers(module, slb_servers)

    json_post = {
        "server": {
            "name": template_server,
        }
    }

    if template_monitor:
        json_post['server']['health-check'] = template_monitor
    elif template_monitor_disable:
        json_post['server']['health-check-disable'] = axapi_enabled_disabled(template_monitor_disable)
    if template_weight:
        json_post['server']['weight'] = template_weight

    slb_server_data = axapi_call_v3(module, axapi_base_url+'slb/template/server/' + template_server, method='GET', body='', signature=signature)

    slb_server_exists = slb_server_data and slb_server_data.get('server') and slb_server_data.get('server').get('name')
    result = ''
    changed=False

    if state == 'absent' and not slb_server_exists:
        result = slb_server_data

    elif state == 'present' and slb_server_exists:
        result = slb_server_data

    elif state == 'absent' and slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/template/server/' + template_server, method='DELETE', body='', signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to delete the server template: %s" % result['response']['err']['msg'])
        changed=True

    elif state == 'present' and not slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/template/server/', method='POST', body=json.dumps(json_post), signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to create the server template: %s" % result['response']['err']['msg'])
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
