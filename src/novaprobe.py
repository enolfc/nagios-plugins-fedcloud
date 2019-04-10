#!/usr/bin/python

# Copyright (C) 2015 SRCE
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse, re
import requests, sys, os, json
import time
import logging

from six.moves.urllib.parse import urlparse

from pymodule import helpers

DEFAULT_PORT = 443
TIMEOUT_CREATE_DELETE = 600
SERVER_NAME = 'cloudmonprobe-servertest'

strerr = ''
num_excp_expand = 0


def get_image_id(glance_url, ks_token, appdb_id):
    next_url = 'v2/images'
    try:
        # TODO: query for the exact image directly once that info is available in glance
        # that should remove the need for the loop
        while next_url:
            images_url  = urlparse.urljoin(glance_url, next_url)
            response = requests.get(images_url, headers = {'x-auth-token': ks_token}, verify=True)
            response.raise_for_status()
            for img in response.json()['images']:
                attrs = json.loads(img.get('APPLIANCE_ATTRIBUTES', '{}'))
                if attrs.get('ad:appid', '') == appdb_id:
                    return img['id']
            next_url = response.json().get('next', '')
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
        helpers.nagios_out('Critical', 'Could not fetch image ID: %s' % helpers.errmsg_from_excp(e), 2)
    except (AssertionError, IndexError, AttributeError) as e:
        helpers.nagios_out('Critical', 'Could not fetch image ID: %s' % str(e), 2)
    helpers.nagios_out('Critical', 'Could not find image ID for AppDB image %s' % appdb_id, 2)


def get_smaller_flavor_id(nova_url, ks_token):
    flavor_url = nova_url + '/flavors/detail'
    # flavors with at least 8GB of disk, sorted by number of cpus
    query = {'minDisk': '8', 'sort_dir': 'asc', 'sort_key': 'vcpus'}
    headers = {'x-auth-token': ks_token}
    try:

        response = requests.get(flavor_url, headers=headers, params=query, verify=True)
        response.raise_for_status()
        flavors = response.json()['flavors']
        # minimum number of CPUs from first result (they are sorted)
        min_cpu = flavors[0]['vcpus']
        # take the first one after ordering by RAM
        return sorted(filter(lambda x: x['vcpus'] == min_cpu, flavors),
                      key=lambda x: x['ram']).pop(0)['id']
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
        helpers.nagios_out('Critical', 'Could not fetch flavor ID: %s' % helpers.errmsg_from_excp(e), 2)
    except (AssertionError, IndexError, AttributeError) as e:
        helpers.nagios_out('Critical', 'Could not fetch flavor ID: %s' % str(e), 2)


class NagiosParser(argparse.ArgumentParser):
    # override default error to fit what nagios expects
    def error(self, message):
        self.exit(3, 'Unknown: error: %s\n' % message)


def main():
    parser = NagiosParser()
    parser.add_argument('--endpoint', dest='endpoint', required=True)
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('--flavor')
    group_img = parser.add_mutually_exclusive_group(required=True)
    group_img.add_argument('--image')
    group_img.add_argument('--appdb-image')
    group_auth = parser.add_argument_group(title="Authentication")
    group_auth.add_argument('--cert')
    group_auth.add_argument('--access-token')
    group_auth.add_argument('--identity-provider', default='egi.eu')
    group_auth.add_argument('--protocol', default='openid')
    parser.add_argument('-t', '--timeout', type=int, default=120)

    opts = parser.parse_args()

    level = logging.DEBUG if opts.verbose else logging.INFO
    # FIXME: log to stdout
    logging.basicConfig(level=level)

    if not opts.cert and not opts.access_token:
        parser.error('cert or access-token not specified')

    if not opts.endpoint.startswith("http"):
        parser.error('expecting http(s) endpotint')

    if opts.cert and not os.path.isfile(opts.cert):
        parser.error('cert file %s does not exist' % opts.cert)
    if opts.access_token and not os.path.isfile(opts.access_token):
        parser.error('access token file %s does not exist' % opts.access_token)

    # 1. Get a valid Keystone token
    access_token = None
    if opts.access_token:
        with open(opts.access_token, 'r') as f:
            access_token = f.read().rstrip('\n')
    auth_classes = [helpers.V3Oidc, helpers.V3Voms, helpers.V2Voms]

    for c in auth_classes:
        try:
            auth = c(endpoint=opts.endpoint, timeout=opts.timeout,
                     access_token=access_token, userca=opts.cert,
                     identity_provider=opts.identity_provider,
                     protocol=opts.protocol)
            ks_token = auth.authenticate()
            if opts.verbose:
                print("Authentication with %s succeded" % c)
            break
        except helpers.AuthenticationException as e:
            # just go ahead
            if opts.verbose:
                print("Authentication with %s failed" % c)
    else:
        # no auth method worked, exit
        helpers.nagios_out('Critical',
                           'Unable to authenticate against keystone',
                           2)

    # Here we have authenticated, ready to execute the actual probe
    tenant_id = auth.project_id
    nova_url = auth.endpoints['compute']
    glance_url = auth.endpoints['image']
    neutron_url = auth.endpoints['network']

    if opts.verbose:
        print('Endpoint: %s' % (opts.endpoint))
        print('Auth token (cut to 64 chars): %.64s' % ks_token)
        print('Project OPS, ID: %s' % tenant_id)
        print( 'Nova: %s' % nova_url)
        print( 'Glance: %s' % glance_url)
        print( 'Neutron: %s' % neutron_url)


    if not opts.image:
        image = get_image_id(glance_url, ks_token, opts.appdb_img)
    else:
        image = opts.image

    if opts.verbose:
        print( "Image: %s" % image)

    if not opts.flavor:
        flavor_id = get_smaller_flavor_id(nova_url, ks_token)
    else:
        # fetch flavor_id for given flavor (resource)
        try:
            headers, payload= {}, {}
            headers.update({'x-auth-token': ks_token})
            response = requests.get(nova_url + '/flavors', headers=headers, cert=opts.cert,
                                    verify=True, timeout=opts.timeout)
            response.raise_for_status()

            flavors = response.json()['flavors']
            flavor_id = None
            for f in flavors:
                if f['name'] == opts.flavor:
                    flavor_id = f['id']
            assert flavor_id is not None
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout, requests.exceptions.HTTPError) as e:
            helpers.nagios_out('Critical', 'could not fetch flavor ID, endpoint does not correctly exposes available flavors: %s' % helpers.errmsg_from_excp(e), 2)
        except (AssertionError, IndexError, AttributeError) as e:
            helpers.nagios_out('Critical', 'could not fetch flavor ID, endpoint does not correctly exposes available flavors: %s' % str(e), 2)

    if opts.verbose:
        print( "Flavor ID: %s" % flavor_id)

    network_id = None
    if neutron_url:
        try:
            headers, payload= {}, {}
            headers = {'content-type': 'application/json', 'accept': 'application/json'}
            headers.update({'x-auth-token': ks_token})
            response = requests.get(neutron_url + '/v2.0/networks', headers=headers,
                                    cert=opts.cert, verify=True,
                                    timeout=opts.timeout)
            response.raise_for_status()
            for network in response.json()['networks']:
                # assume first available active network owned by the tenant is ok
                if network['status'] == 'ACTIVE' and network['tenant_id'] == tenant_id:
                    network_id = network['id']
                    if opts.verbose:
                        print( "Network id: %s" % network_id)
                        break
            else:
                if opts.verbose:
                    print("No tenant-owned network found, hoping VM creation will still work...")
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout, requests.exceptions.HTTPError,
                AssertionError, IndexError, AttributeError) as e:
            helpers.nagios_out('Critical', 'Could not get network id: %s' % helpers.errmsg_from_excp(e), 2)

    else:
        if opts.verbose:
            print("Skipping network discovery as there is no neutron endpoint")

    # create server
    try:
        headers, payload= {}, {}
        headers = {'content-type': 'application/json', 'accept': 'application/json'}
        headers.update({'x-auth-token': ks_token})
        payload = {
            'server': {
                'name': SERVER_NAME,
                'imageRef': image,
                'flavorRef': flavor_id,
            }
        }
        if network_id:
            payload['server']['networks'] = [{'uuid': network_id}]
        response = requests.post(nova_url + '/servers', headers=headers,
                                    data=json.dumps(payload),
                                    cert=opts.cert, verify=True,
                                    timeout=opts.timeout)
        response.raise_for_status()
        server_id = response.json()['server']['id']
        if opts.verbose:
            print("Creating server:%s name:%s" % (server_id, SERVER_NAME))
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout, requests.exceptions.HTTPError,
            AssertionError, IndexError, AttributeError) as e:
        if opts.verbose:
            print('Error from server while creating server: %s' % response.text)
        helpers.nagios_out('Critical', 'Could not launch server from image UUID:%s: %s' % (image, helpers.errmsg_from_excp(e)), 2)


    i, s, e, sleepsec, tss = 0, 0, 0, 1, 3
    server_createt, server_deletet= 0, 0
    server_built = False
    st = time.time()
    if opts.verbose:
        sys.stdout.write('Check server status every %ds: ' % (sleepsec))
    while i < TIMEOUT_CREATE_DELETE/sleepsec:
        # server status
        try:
            headers, payload= {}, {}
            headers.update({'x-auth-token': ks_token})
            response = requests.get(nova_url + '/servers/%s' % (server_id),
                                    headers=headers, cert=opts.cert,
                                    verify=True,
                                    timeout=opts.timeout)
            response.raise_for_status()
            status = response.json()['server']['status']
            if opts.verbose:
                sys.stdout.write(status+' ')
                sys.stdout.flush()
            if 'ACTIVE' in status:
                server_built = True
                et = time.time()
                break
            if 'ERROR' in status:
                et = time.time()
                if opts.verbose:
                    print("Error from nova: %s" % response.json()['server'].get('fault', ''))
                break
            time.sleep(sleepsec)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout, requests.exceptions.HTTPError,
                AssertionError, IndexError, AttributeError) as e:
            if i < tss and opts.verbose:
                sys.stdout.write('\n')
                sys.stdout.write('Try to fetch server:%s status one more time. Error was %s\n' % (server_id,
                                                                                                helpers.errmsg_from_excp(e)))
                sys.stdout.write('Check server status every %ds: ' % (sleepsec))
            else:
                helpers.nagios_out('Critical', 'could not fetch server:%s status: %s' % (server_id, helpers.errmsg_from_excp(e)), 2)
        i += 1
    else:
        if opts.verbose:
            sys.stdout.write('\n')
        helpers.nagios_out('Critical', 'could not create server:%s, timeout:%d exceeded' % (server_id, TIMEOUT_CREATE_DELETE), 2)

    server_createt = round(et - st, 2)

    if server_built:
        if opts.verbose:
            print("\nServer created in %.2f seconds" % (server_createt))

    # server delete
    try:
        headers, payload= {}, {}
        headers.update({'x-auth-token': ks_token})
        response = requests.delete(nova_url + '/servers/%s' %
                                    (server_id), headers=headers,
                                    cert=opts.cert, verify=True,
                                    timeout=opts.timeout)
        if opts.verbose:
            print( "Trying to delete server=%s" % server_id)
        response.raise_for_status()
    except (requests.exceptions.ConnectionError,
            requests.exceptions.Timeout, requests.exceptions.HTTPError,
            AssertionError, IndexError, AttributeError) as e:
        if opts.verbose:
            print( 'Error from server while deleting server: %s' % response.text)
        helpers.nagios_out('Critical', 'could not execute DELETE server=%s: %s' % (server_id, helpers.errmsg_from_excp(e)), 2)

    # waiting for DELETED status
    i = 0
    server_deleted = False
    st = time.time()
    if opts.verbose:
        sys.stdout.write('Check server status every %ds: ' % (sleepsec))
    while i < TIMEOUT_CREATE_DELETE/sleepsec:
        # server status
        try:
            headers, payload= {}, {}
            headers.update({'x-auth-token': ks_token})

            response = requests.get(nova_url + '/servers', headers=headers,
                                    cert=opts.cert, verify=True,
                                    timeout=opts.timeout)
            servfound = False
            for s in response.json()['servers']:
                if server_id == s['id']:
                    servfound = True
                    response = requests.get(nova_url + '/servers/%s' %
                                            (server_id), headers=headers,
                                            cert=opts.cert, verify=True,
                                            timeout=opts.timeout)
                    response.raise_for_status()
                    status = response.json()['server']['status']
                    if opts.verbose:
                        sys.stdout.write(status+' ')
                        sys.stdout.flush()
                    if status.startswith('DELETED'):
                        server_deleted = True
                        et = time.time()
                        break

            if not servfound:
                server_deleted = True
                et = time.time()
                if opts.verbose:
                    sys.stdout.write('DELETED')
                    sys.stdout.flush()
                break

            time.sleep(sleepsec)
        except (requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                requests.exceptions.HTTPError, AssertionError,
                IndexError, AttributeError) as e:

            server_deleted = True
            et = time.time()

            if opts.verbose:
                sys.stdout.write('\n')
                sys.stdout.write('Could not fetch server:%s status: %s - server is DELETED' % (server_id,
                                                                                                helpers.errmsg_from_excp(e)))
                break
        i += 1
    else:
        if opts.verbose:
            sys.stdout.write('\n')
        helpers.nagios_out('Critical', 'could not delete server:%s, timeout:%d exceeded' % (server_id, TIMEOUT_CREATE_DELETE), 2)

    server_deletet = round(et - st, 2)
    if opts.verbose:
        print( "\nServer=%s deleted in %.2f seconds" % (server_id, server_deletet))

    if server_built and server_deleted:
        helpers.nagios_out('OK', 'Compute instance=%s created(%.2fs) and destroyed(%.2fs)' % (server_id, server_createt, server_deletet), 0)
    elif server_built:
        # Built but not deleted
        helpers.nagios_out('Critical', 'Compute instance=%s created (%.2fs) but not destroyed(%.2fs)' % (server_id, server_createt, server_deletet), 2)
    else:
        # not built but deleted
        helpers.nagios_out('Critical', 'Compute instance=%s created with error(%.2fs) and destroyed(%.2fs)' % (server_id, server_createt, server_deletet), 2)


main()
