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
module: a10_service_group_axapi3
version_added: 3.X
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' service groups.
description:
    - Manage SLB (Server Load Balancing) service-group objects on A10 Networks devices via aXAPIv3.
author: "David Haupt 2017 (pdjopensource@gmail.com), Eric Chou (@ericchou) 2016, Mischa Peters (@mischapeters) 2014"
notes:
    - Requires A10 Networks aXAPI 3.0
    - When a server doesn't exist and is added to the service-group the server will be created.
extends_documentation_fragment: a10
options:
  service_group:
    description:
      - The SLB (Server Load Balancing) service-group name
    required: true
    default: null
    aliases: ['name', 'service', 'pool', 'group']
  state:
    description:
      - The SLB service-group state
    required: false
    default: present
  service_group_protocol:
    description:
      - The SLB service-group protocol of TCP or UDP.
    required: false
    default: tcp
    aliases: ['proto', 'protocol']
    choices: ['tcp', 'udp']
  service_group_method:
    description:
      - The SLB service-group load balancing method, such as round-robin or weighted-rr.
    required: false
    default: round-robin
    aliases: ['method']
    choices:
        - 'dst-ip-hash'
        - 'dst-ip-only-hash'
        - 'fastest-response'
        - 'least-request'
        - 'src-ip-hash'
        - 'src-ip-only-hash'
        - 'weighted-rr'
        - 'round-robin'
        - 'round-robin-strict'
        - 'odd-even-hash'
        - 'least-connection'
        - 'service-least-connection'
        - 'weighted-least-connection'
        - 'service-weighted-least-connection'
        - 'stateless-dst-ip-hash'
        - 'stateless-per-pkt-round-robin'
        - 'stateless-src-dst-iphash'
        - 'stateless-src-dst-ip-only-hash'
        - 'stateless-src-ip-hash'
        - 'stateless-src-ip-only-hash'
  member_list:
    description:
      - A list of servers to add to the service group. Each list item should be a
        dictionary which specifies the C(server:) and C(port:), but can also optionally
        specify the C(status:). See the examples below for details.
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

EXAMPLES = '''
# Create a new service-group
- a10_service_group_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    service_group: sg-80-tcp
    state: present
    member_list:
      - name: myserver1
        host: 10.1.2.123
        port: 8080
        member-state: enable
      - name: myserver2
        fqdn-name: myserver.fqdn.com
        port: 8080
        member-state: disable-with-health-check
      - name: myserver3
        port: 8080
        member-state: disable

'''

RETURN = '''
content:
  description: the full info regarding the slb_service_group
  returned: success
  type: string
  sample: "mynewservicegroup"

'''
import json

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.urls import url_argument_spec
from ansible.module_utils.a10 import axapi_call_v3, a10_argument_spec, axapi_authenticate_v3, axapi_failure
from ansible.module_utils.a10 import AXAPI_PORT_PROTOCOLS

VALID_MEMBER_FIELDS = ['name', 'port', 'fqdn-name', 'host', 'member-state']

def validate_servers(module, member_list):
    for item in member_list:
        for key in item:
            if key not in VALID_MEMBER_FIELDS:
                module.fail_json(msg="invalid member list field (%s), must be one of: %s" % (key, ','.join(VALID_MEMBER_FIELDS)))

        # validate the server name is present
        if 'name' not in item:
            module.fail_json(msg="member-list definitions must define the name field")

        # validate the port number is present and an integer
        if 'port' in item:
            try:
                item['port'] = int(item['port'])
            except:
                module.fail_json(msg="server port definitions must be integers")
        else:
            module.fail_json(msg="server definitions must define the port field")

def main():
    argument_spec = a10_argument_spec()
    argument_spec.update(url_argument_spec())
    argument_spec.update(
        dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            service_group=dict(type='str', aliases=['name', 'service', 'pool'], required=True),
            service_group_protocol=dict(type='str', aliases=['protocol'], choices=['tcp', 'udp'], default='tcp'),
            service_group_method=dict(type='str', aliases=['method'], choices=[
		'dst-ip-hash', 'dst-ip-only-hash', 'fastest-response', 'least-request', 'src-ip-hash', 'src-ip-only-hash', 'weighted-rr',
		'round-robin', 'round-robin-strict', 'odd-even-hash', 'least-connection', 'service-least-connection', 'weighted-least-connection',
		'service-weighted-least-connection','stateless-dst-ip-hash', 'stateless-per-pkt-round-robin', 'stateless-src-dst-iphash',
		'stateless-src-dst-ip-only-hash', 'stateless-src-ip-hash', 'stateless-src-ip-only-hash'], default='round-robin'),
            server_status=dict(type='str', default='enable', aliases=['action'], choices=['enable', 'disable']),
            members_list=dict(type='list', aliases=['servers', 'members'], default=[])
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

    slb_sg = module.params['service_group']
    slb_sg_protocol = module.params['service_group_protocol']
    slb_lb_method = module.params['service_group_method']
    slb_servers = module.params['members_list']

    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    if slb_lb_method in ['dst-ip-hash', 'dst-ip-only-hash', 'fastest-response', 'least-request', 'src-ip-hash, src-ip-only-hash', 'weighted-rr', 
			 'round-robin', 'round-robin-strict', 'odd-even-hash']:
	method = 'lb-method'
    elif slb_lb_method in ['least-connection', 'service-least-connection', 'weighted-least-connection', 'service-weighted-least-connection']:
	method = 'lc-method'
    else:
	method = 'stateless-lb-method'

    # validate the server data list structure
    validate_servers(module, slb_servers)

    json_post = {
        "service-group": {
            "name": slb_sg,
            "protocol": slb_sg_protocol,
    	    method: slb_lb_method,
	        "member-list": slb_servers 
        }
    }

    slb_server_data = axapi_call_v3(module, axapi_base_url+'slb/service-group/' + slb_sg, method='GET', body='', signature=signature)

    slb_server_exists = slb_server_data and slb_server_data.get('service-group') and slb_server_data.get('service-group').get('name')
    result = ''
    changed=False

    if state == 'absent' and not slb_server_exists:
        result = slb_server_data

    elif state == 'present' and slb_server_exists:
        result = slb_server_data

    elif state == 'absent' and slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/service-group/' + slb_sg, method='DELETE', body='', signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to delete the service-group: %s" % result['response']['err']['msg'])
        changed=True

    elif state == 'present' and not slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'slb/service-group/', method='POST', body=json.dumps(json_post), signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to create the service-group: %s" % result['response']['err']['msg'])
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
