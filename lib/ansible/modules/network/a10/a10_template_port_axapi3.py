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
module: a10_template_port_axapi3
version_added: 3.X
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' server port templates.
description:
    - Manage SLB (Server Load Balancing) server port objects on A10 Networks devices via aXAPIv3.
author: "David Haupt 2017 (pdjopensource@gmail.com), Eric Chou (@ericchou) 2016, Mischa Peters (@mischapeters) 2014"
notes:
    - Requires A10 Networks aXAPI 3.0
    - For now only http health monitors are implemented.
extends_documentation_fragment: a10
options:
  template_port:
    description:
      - The SLB (Server Load Balancing) template port name
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
  source_nat:
    description:
      - Specifies the IP NAT pool to use for assigning source IP addresses to client traffic sent to ports that use this template. When the ACOS device performs NAT for a port that is bound to the template, the device selects an IP address from the pool.
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
    template_port: my_template_port
    state: present
    health_check: my_health_check

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
            template_port=dict(type='str', aliases=['name', 'template'], required=True),
            health_check=dict(type='str', aliases=['monitor']),
            health_check_disable=dict(type='str'),
            source_nat=dict(type='str')
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

    template_port = module.params['template_port']
    template_monitor = module.params['health_check']
    template_monitor_disable = module.params['health_check_disable']
    template_snat = module.params['source_nat']

    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    json_post = {
        "port": {
            "name": template_port
        }
    }

    if template_monitor:
        json_post['port']['health-check'] = template_monitor
    elif template_monitor_disable:
        json_post['port']['health-check-disable'] = axapi_enabled_disabled(template_monitor_disable)
    if template_snat:
        json_post['port']['source-nat'] = template_snat

    slb_server_data = axapi_call_v3(module, axapi_base_url+'slb/template/port/' + template_port, method='GET', body='', signature=signature)

    slb_server_exists = slb_server_data and slb_server_data.get('port') and slb_server_data.get('port').get('name')
    result = ''
    changed=False

    if state == 'absent' and not slb_server_exists:
        result = slb_server_data

    elif state == 'present' and slb_server_exists:
        result = slb_server_data

    elif state == 'absent' and slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/template/port/' + template_port, method='DELETE', body='', signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to delete the port template: %s" % result['response']['err']['msg'])
        changed=True

    elif state == 'present' and not slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/template/port/', method='POST', body=json.dumps(json_post), signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to create the port template: %s" % result['response']['err']['msg'])
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
