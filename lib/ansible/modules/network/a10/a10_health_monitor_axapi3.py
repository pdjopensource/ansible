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
module: a10_health_monitor_axapi3
version_added: 3.X
short_description: Manage A10 Networks AX/SoftAX/Thunder/vThunder devices' health monitors.
description:
    - Manage SLB (Server Load Balancing) health monitors objects on A10 Networks devices via aXAPIv3.
author: "David Haupt 2017 (pdjopensource@gmail.com), Eric Chou (@ericchou) 2016, Mischa Peters (@mischapeters) 2014"
notes:
    - Requires A10 Networks aXAPI 3.0
    - For now only http health monitors are implemented.
extends_documentation_fragment: a10
options:
  health_monitor:
    description:
      - The SLB (Server Load Balancing) health monitor name
    required: true
    default: null
    aliases: ['name', 'monitor']
  health_monitor_type:
    description:
      - The SLB health monitor method.
    required: false
    default: http
    aliases: ['method', 'type']
    choices: ['icmp', 'tcp', 'http']
  state:
    description:
      - The health monitor state
    default: present
    choices: ['present','absent']
  retry:
    description:
      - Specify the Healthcheck Retries (Retry Count (default 3))
    required: false
    default: 3
  up_retry:
    description:
      - Specify the Healthcheck Retries before declaring target up (Up-retry count (default 1))
    required: false
    default: 1
  interval:
    description:
      - Specify the health check interval in seconds.
    required: false
    default: 5
  timeout:
    description:
      - Specify the health check interval in seconds.
    required: false
    default: 5
  url_type:
    description:
      - Specify the HTTP method to use - GET, POST or HEAD.
    required: false
    choices: ['GET', 'POST', 'HEAD']
    default: GET
  url_path:
    description:
      - Specify URL path, default is “/”
    required: false
    default: '/'
  http_port:
    description:
      - Specify the HTTP port number.
    required: false
    default: 80
  text_regex:
    description:
      - Specify text expected with Regex
    required: false
    default: '*'
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
- a10_health_monitor_axapi3:
    host: a10.mydomain.com
    username: myadmin
    password: mypassword
    health_monitor: hm_http
    health_monitor_type: http
    url_path: '/index.jsp'
    http_port: 8080
    text_regex: '200 OK'

'''

RETURN = '''
content:
  description: the full info regarding the health monitor
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
            state=dict(type='str', default='present', choices=['present','absent']),
            health_monitor=dict(type='str', aliases=['name', 'monitor'], required=True),
            health_monitor_type=dict(type='str', aliases=['method','type'], choices=['icmp','tcp', 'http'], default='http'),
            retry=dict(type='int', default=3),
            up_retry=dict(type='int', default=1),
            interval=dict(type='int', default=5),
            timeout=dict(type='int', default=5),
            url_type=dict(type='str', choices=['GET','POST', 'HEAD'], default='GET'),
            url_path=dict(type='str', default='/'),
            http_port=dict(type='int', default=80),
            text_regex=dict(type='str', default='*')
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

    health_hm = module.params['health_monitor']
    health_hm_type = module.params['health_monitor_type']
    health_retry = module.params['retry']
    health_up_retry = module.params['up_retry']
    health_interval = module.params['interval']
    health_timeout = module.params['timeout']
    health_url_type = module.params['url_type']
    health_url_path = module.params['url_path']
    health_http_port = module.params['http_port']
    health_text_regex = module.params['text_regex']

    axapi_base_url = 'https://{}/axapi/v3/'.format(host)
    axapi_auth_url = axapi_base_url + 'auth/'
    signature = axapi_authenticate_v3(module, axapi_auth_url, username, password)

    # validate the server data list structure
    #validate_servers(module, slb_servers)

    json_post = {
        "monitor": {
            "name": health_hm,
            "retry": health_retry,
            "up-retry": health_up_retry,
#            "timeout": 5,
            "method": {
                health_hm_type: {
                    "http": 1,
                    "http-expect": 1,
                    "http-port": health_http_port,
                    "http-url": 1,
                    "text-regex": health_text_regex,
                    "url-path": health_url_path,
                    "url-type": health_url_type
                }
            }
        }
    }

    slb_server_data = axapi_call_v3(module, axapi_base_url+'health/monitor/' + health_hm, method='GET', body='', signature=signature)

    slb_server_exists = slb_server_data and slb_server_data.get('monitor') and slb_server_data.get('monitor').get('name')
    result = ''
    changed=False

    if state == 'absent' and not slb_server_exists:
        result = slb_server_data

    elif state == 'present' and slb_server_exists:
        result = slb_server_data

    elif state == 'absent' and slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'health/monitor/' + health_hm, method='DELETE', body='', signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to delete the health monitor: %s" % result['response']['err']['msg'])
        changed=True

    elif state == 'present' and not slb_server_exists:
        result = axapi_call_v3(module, axapi_base_url+'health/monitor/', method='POST', body=json.dumps(json_post), signature=signature)
        if axapi_failure(result):
            axapi_call_v3(module, axapi_base_url + 'logoff/', method='POST', body='', signature=signature)
            module.fail_json(msg="failed to create the health monitor: %s" % result['response']['err']['msg'])
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
