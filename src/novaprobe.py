import argparse
import json
import logging
import time
import sys


import glanceclient
from keystoneauth1.identity import v3
from keystoneauth1.exceptions.base import ClientException
from keystoneauth1 import session
from keystoneclient.v3 import client
import novaclient.client
from novaclient.exceptions import NotFound
from openstack_voms_auth_type import v3 as vomsv3
from openstack_voms_auth_type import v2 as vomsv2


TIMEOUT_CREATE_DELETE = 600


def nagios_out(status, msg, retcode):
    sys.stdout.write(status +" : " + msg + "\n")
    sys.exit(retcode)


class Authenticator(object):
    def __init__(self, opts):
        self.ca_path = opts.ca_path
        self.endpoint = opts.endpoint

    def get_auth(self, project_id=None):
        raise NotImplemented

    def find_ops_project(self):
        '''Get scoped session in the ops project if available'''
        s = session.Session(auth=self.get_auth(), verify=self.ca_path)
        ks = client.Client(session=s)
        for project in ks.auth.projects():
            print("*" * 80)
            print(project)
            # Discovery based on name :/
            if 'ops' in project.name:
                break
        return project

    def authenticate(self):
        self.get_auth()
        try:
            project = self.find_ops_project()
            return session.Session(auth=self.get_auth(project.id),
                                   verify=self.ca_path)
        except ClientException as e:
            logging.debug("Unable to login %s", e)
            return None


class OIDCAuthenticator(Authenticator):
    def __init__(self, opts):
        super(OIDCAuthenticator, self).__init__(opts)
        if opts.access_token:
            with open(opts.access_token, 'r') as f:
                self.access_token = f.read().rstrip("\n")
        else:
            logging.debug("No access token provided, skipping OIDC")
            raise AttributeError
        self.identity_provider = opts.identity_provider
        self.protocol = opts.protocol

    def get_auth(self, project_id=None):
        return v3.OidcAccessToken(auth_url=self.endpoint,
                                  identity_provider=self.identity_provider,
                                  protocol=self.protocol,
                                  access_token=self.access_token,
                                  project_id=project_id)


class VomsV3Authenticator(Authenticator):
    def __init__(self, opts):
        super(VomsV3Authenticator, self).__init__(opts)
        if opts.cert:
            self.cert = opts.cert
        else:
            logging.debug("No certificate provided, skipping VOMS v3")
            raise AttributeError
        self.identity_provider = opts.identity_provider
        self.protocol = 'mapped'

    def get_auth(self, project_id=None):
        return vomsv2.VomsV2AuthPlugin(auth_url=self.endpoint,
                                       x509_user_proxy=self.cert,
                                       project_id=project_id)


class VomsV2Authenticator(Authenticator):
    def __init__(self, opts):
        super(VomsV2Authenticator, self).__init__(opts)
        if opts.cert:
            self.cert = opts.cert
        else:
            logging.debug("No certificate provided, skipping VOMS v2")
            raise AttributeError

    def get_auth(self, project_id=None):
        return vomsv2.VomsV2AuthPlugin(auth_url=self.endpoint,
                                       x509_user_proxy=self.cert,
                                       project_id=project_id)


def authenticate(opts):
    methods = [OIDCAuthenticator, VomsV3Authenticator, VomsV2Authenticator]
    for m in methods:
        try:
            session = m(opts).authenticate()
            if session:
                return session
            logging.info("Unable to authenticate with %s", m)
        except AttributeError:
            logging.debug("Skipping auth with %s",  m)
            continue
    logging.error("Unable to authenticate with any supported methods")
    nagios_out('Critical',
               'Unable to authenticate with any supported methods',
               2)


def get_smaller_flavor_id(nova):
    # flavors with at least 8GB of disk, sorted by number of cpus
    flvs = nova.flavors.list(min_disk=8, sort_dir='asc', sort_key='vcpus')
    min_cpu = flvs[0].vcpus
    return sorted(filter(lambda x: x.vcpus == min_cpu, flvs),
                  key=lambda x: x.ram).pop(0).id


def get_appdb_image(glance, appdb_id):
    for img in glance.images.list():
        attrs = json.loads(img.get('APPLIANCE_ATTRIBUTES', '{}'))
        if attrs.get('ad:appid', '') == appdb_id:
            return img.id
    nagios_out('Critical',
               'Could not find image ID for AppDB image %s' % appdb_id,
               2)


def wait_for_server(nova, server, expected_status):
    status_reached = False
    delay = 1
    i = 0
    while i < TIMEOUT_CREATE_DELETE/delay:
        try:
            server = nova.servers.get(server)
            if server.status == expected_status:
                return True
        except NotFound:
            if expected_status == 'DELETED':
                return True
        logging.debug("Waiting some extra %s seconds until the server is %s",
                      delay, expected_status)
        time.sleep(delay)
        i += 1
    return expected_status

def main():
    parser = argparse.ArgumentParser()

    parser = argparse.ArgumentParser()
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
    parser.add_argument('--ca-path', '--capath', default='/etc/grid-security/certificates')

    opts = parser.parse_args()

    level = logging.DEBUG if opts.verbose else logging.INFO
    logging.basicConfig(level=level)

    session = authenticate(opts)
    nova = novaclient.client.Client(2, session=session)
    glance = glanceclient.Client(2, session=session)

    flavor = opts.flavor
    if not flavor:
        flavor = get_smaller_flavor_id(nova)
        logging.info('Using %s as flavor' % flavor)

    image = opts.image
    if not image:
        image = get_appdb_image(glance, opts.appdb_image)
        logging.info('Using %s as image' % image)

    # TODO: Clean up any previous monitoring servers
    # build server
    st = time.time()
    server = nova.servers.create('monitoring', image, flavor)
    server_started = wait_for_server(nova, server, 'ACTIVE')
    creation_time = round(time.time() - st, 2)
    st = time.time()
    server.delete()
    server_deleted = wait_for_server(nova, server, 'DELETED')
    deletion_time = round(time.time() - st, 2)
    if server_started:
        if server_deleted:
            nagios_out(
                'OK', ('Compute instance=%s created(%.2fs) and destroyed(%.2fs)'
                       % (server_id, creation_time, deletion_time)), 0)

#__init__(self, auth_url, identity_provider, protocol, access_token, **kwargs)

if __name__ == '__main__':
    main()
