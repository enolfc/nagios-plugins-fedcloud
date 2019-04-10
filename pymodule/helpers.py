import json
import os
import sys

import requests
from six.moves.urllib.parse import urlparse


strerr = ''
num_excp_expand = 0


class AuthenticationException(Exception):
    pass


class AuthenticationMethod(object):
    def __init__(self, **kwargs):
        self.endpoint = kwargs.get('endpoint')
        self.timeout = kwargs.get('timeout')
        self.endpoints = dict(compute=None, image=None, network=None)

    def _authenticate(self):
        raise NotImplementedError()

    def authenticate(self):
        o = urlparse(self.endpoint)
        if o.scheme != 'https':
            raise AuthenticationException('Connection error %s - Probe expects'
                                          ' HTTPS endpoint' % self.endpoint)

        suffix = o.path.rstrip('/')
        if suffix.endswith('v2.0') or suffix.endswith('v3'):
            suffix = os.path.dirname(suffix).rstrip('/')

        base_url = o.scheme + '://' + o.netloc + suffix
        token = self._authenticate(base_url)
        self.get_info()
        return token


class KeystoneV3(AuthenticationMethod):
    def __init__(self, **kwargs):
        self.access_token = kwargs.get('access_token')
        self.identity_provider = kwargs.get('identity_provider')
        self.protocol = kwargs.get('protocol')
        super(KeystoneV3, self).__init__(**kwargs)

    def get_token(self, base_url):
        raise NotImplementedError()

    def _authenticate(self, base_url):
        token = self.get_token(base_url)

        try:
            # use unscoped token to get a list of allowed projects mapped to
            # ops VO from atuh token
            headers = {'content-type': 'application/json',
                       'accept': 'application/json',
                       'x-auth-token': token}
            url = base_url + '/v3/auth/projects',
            response = requests.get(url, headers=headers, data=None,
                                    timeout=self.timeout, verify=True)
            response.raise_for_status()
            projects = response.json()['projects']
            project = {}
            for p in projects:
                if 'ops' in p['name']:
                    project = p
                    break
            else:
                # just take one
                project = projects.pop()
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch allowed projects '
                                          'from response: %s'
                                          % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException(
                'Connection error %s - %s' % (url, errmsg_from_excp(e)))

        try:
            # get scoped token for allowed project
            url = base_url + '/v3/auth/tokens',
            headers = {'content-type': 'application/json',
                       'accept': 'application/json'}
            payload = {"auth": {"identity": {"methods": ["token"],
                                "token": {"id": token}},
                                "scope": {"project": {"id": project["id"]}}}}
            response = requests.post(url, headers=headers,
                                     data=json.dumps(payload), verify=True,
                                     timeout=self.timeout)
            response.raise_for_status()
            token = response.headers['X-Subject-Token']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch scoped keystone '
                                          'token for %s from response: %s'
                                          % (project, errmsg_from_excp(e)))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException(
                'Connection error %s - %s' % (url, errmsg_from_excp(e)))

        self.token_info = response.json()
        self.project = project
        return token

    def get_info(self):
        try:
            self.project_id = self.token_info['token']['project']['id']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not get fetch project id: %s'
                                          % errmsg_from_excp(e))
        try:
            service_catalog = self.token_info['token']['catalog']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not get fetch catalog: %s'
                                          % errmsg_from_excp(e))
        try:
            for e in service_catalog:
                if e['type'] in self.endpoints:
                    for ep in e['endpoints']:
                        if ep['interface'] == 'public':
                            self.endpoints[e['type']] = ep['url']
            assert (self.endpoints['compute'] and self.endpoints['image'])
        except(KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException('Could not fetch service URL: %s'
                                          % errmsg_from_excp(e))


class V3Oidc(KeystoneV3):
    def __init__(self, **kwargs):
        self.access_token = kwargs.get('access_token')
        super(V3Oidc, self).__init__(**kwargs)

    def get_token(self, base_url):
        try:
            auth_path = ('/v3/OS-FEDERATION/identity_providers/%s/protocols/'
                         '%s/auth' % (self.identity_provider, self.protocol))
            url = base_url + auth_path

            headers = {
                'Authorization': 'Bearer %s' % self.access_token,
                'accept': 'application/json'
            }

            response = requests.post(url, headers=headers,
                                     timeout=self.timeout, verify=True)
            response.raise_for_status()
            return response.headers['X-Subject-Token']
        except(KeyError, IndexError) as e:
            raise AuthenticationException(
                'Could not fetch unscoped keystone token from response: %s'
                % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException(
                'Connection error %s - %s' % (url, errmsg_from_excp(e)))


class V3Voms(KeystoneV3):
    def __init__(self, **kwargs):
        self.userca = kwargs.get('userca')
        super(V3Voms, self).__init__(**kwargs)

    def get_token(self, base_url):
        try:
            auth_path = ('/v3/OS-FEDERATION/identity_providers/%s/protocols/'
                         'mapped/auth' % self.identity_provider)
            url = base_url + auth_path

            headers = {'accept': 'application/json'}

            response = requests.post(url, headers=headers, cert=self.userca,
                                     verify=True, timeout=self.timeout)
            response.raise_for_status()
            return response.headers['X-Subject-Token']
        except(KeyError, IndexError) as e:
            raise AuthenticationException(
                'Could not fetch unscoped keystone token from response: %s'
                % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException(
                'Connection error %s - %s' % (url, errmsg_from_excp(e)))


class V2Voms(AuthenticationMethod):
    def __init__(self, **kwargs):
        self.userca = kwargs.get('userca')
        super(V2Voms, self).__init__(**kwargs)

    def _authenticate(self, base_url):
        try:
            # fetch unscoped token
            url = base_url + '/v2.0/tokens'
            headers = {'content-type': 'application/json',
                       'accept': 'application/json'}
            payload = {'auth': {'voms': True}}
            response = requests.post(url, headers=headers,
                                     data=json.dumps(payload),
                                     cert=self.userca,
                                     verify=True, timeout=self.timeout)
            response.raise_for_status()
            token = response.json()['access']['token']['id']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch unscoped keystone '
                                          'token from response: %s'
                                          % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException('Connection error %s - %s'
                                          % (url, errmsg_from_excp(e)))

        try:
            # use unscoped token to get a list of allowed tenants mapped to
            # ops VO from VOMS proxy cert
            url = base_url + '/v2.0/tenants'

            headers = {'content-type': 'application/json',
                       'accept': 'application/json',
                       'x-auth-token': token}
            response = requests.get(url, headers=headers, data=None,
                                    cert=self.userca, verify=True,
                                    timeout=self.timeout)
            response.raise_for_status()
            tenants = response.json()['tenants']
            tenant = ''
            for t in tenants:
                if 'ops' in t['name']:
                    tenant = t['name']
                    break
            else:
                # just take one
                tenant = tenants.pop()['name']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch allowed tenants '
                                          'from response: %s'
                                          % errmsg_from_excp(e))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException('Connection error %s - %s'
                                          % (url, errmsg_from_excp(e)))

        try:
            # get scoped token for allowed tenant
            url = base_url + '/v2.0/tokens'
            headers = {'content-type': 'application/json',
                       'accept': 'application/json'}
            payload = {'auth': {'voms': True, 'tenantName': tenant}}
            response = requests.post(url, headers=headers,
                                     data=json.dumps(payload),
                                     cert=self.userca, verify=True,
                                     timeout=self.timeout)
            response.raise_for_status()
            token = response.json()['access']['token']['id']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch scoped keystone '
                                          'token for %s from response: %s'
                                          % (tenant, errmsg_from_excp(e)))
        except (requests.exceptions.ConnectionError,
                requests.exceptions.HTTPError) as e:
            raise AuthenticationException('Connection error %s - %s'
                                          % (url, errmsg_from_excp(e)))

        self.token_info = response.json()
        self.project = tenant
        return token

    def get_info(self):
        try:
            self.project_id = (
                self.token_info['access']['token']['tenant']['id'])
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch id for tenant: %s'
                                          % errmsg_from_excp(e))

        try:
            service_catalog = self.token_info['access']['serviceCatalog']
        except(KeyError, IndexError) as e:
            raise AuthenticationException('Could not fetch service catalog: %s'
                                          % errmsg_from_excp(e))

        try:
            for e in service_catalog:
                if e['type'] in self.endpoints:
                    self.endpoints[e['type']] = e['endpoints'][0]['publicURL']
            assert (self.endpoints['compute'] and self.endpoints['image'])
        except(KeyError, IndexError, AssertionError) as e:
            raise AuthenticationException('Could not fetch service URL: %s'
                                          % errmsg_from_excp(e))


def nagios_out(status, msg, retcode):
    sys.stdout.write(status+": "+msg+"\n")
    sys.exit(retcode)


def errmsg_from_excp(e, level=5):
    global strerr, num_excp_expand
    if isinstance(e, Exception) and getattr(e, 'args', False):
        num_excp_expand += 1
        if not errmsg_from_excp(e.args):
            return strerr
    elif isinstance(e, dict):
        for s in e.iteritems():
            errmsg_from_excp(s)
    elif isinstance(e, list):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, tuple):
        for s in e:
            errmsg_from_excp(s)
    elif isinstance(e, str):
        if num_excp_expand <= level:
            strerr += e + ' '
