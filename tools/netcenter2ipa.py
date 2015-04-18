#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals

import os
import pwd
import codecs
import sys
import getpass
import httplib2
import base64

from lxml import objectify
from lxml import etree

from ipaserver.plugins.ldap2 import ldap2
from ipalib import api
import ipalib.errors

"""
from ipalib import api
api.bootstrap_with_global_options(context='example', in_server=True)
api.finalize()
if api.env.in_server:
    api.Backend.ldap2.connect(
        ccache=api.Backend.krb.default_ccname()
     )
else:
    api.Backend.rpcclient.connect()

from ipalib.plugins.dns import DNSName
./.python_history:api.Command.dnsrecord_find(DNSName('test55.example.com'))

 result = api.Command.dnsrecord_find(nnzone, u'test55')['result']
"""

def netcenterHosts(hosts, basicAuth, netgroup, ipv6=False):
    method = 'GET'
    url = 'https://www.netcenter.ethz.ch/netcenter/rest/nameToIP/usedIps/'
    url += 'v6/' if ipv6 else 'v4/'
    url += netgroup
    headers = {
        'Host': 'www.netcenter.ethz.ch',
        'Authorization': basicAuth, 'Content-Type': 'text/xml',
        'User-Agent': 'curl/7.37.0', 'Accept': '*/*',
    }
    http = httplib2.Http()
    response, content = http.request(url, method=method, headers=headers, body=None)
    try:
        usedIps = objectify.fromstring(content)
    except:
        print(content)
        raise
    for usedIp in usedIps.usedIp:
        fqdn = str(usedIp.fqname)
        fqdn = fqdn.lstrip('+').strip('.')
        hosts.setdefault(fqdn, [None, None])
        try:
            hosts[fqdn][int(bool(ipv6))] = unicode(usedIp.ip)
        except:
            print( etree.tostring(usedIp, pretty_print=True) )
            raise

def main():

    netgroup=sys.argv[1]

    print('Authenticating to FreeIPA...')
    pwfn = os.path.expanduser('~/.nethz')
    with codecs.open(pwfn, 'r', 'utf-8') as pwf:
        comment = pwf.readline()
        unpw = base64.b64decode(pwf.read())
        username, password = unpw.split('\n', 1)
    basicAuth = 'Basic %s' % base64.b64encode('%s:%s' % (username, password))

    api.bootstrap(context='example', in_server=True)
    api.finalize()
    if api.env.in_server:
        api.Backend.ldap2.connect(ccache=api.Backend.krb.default_ccname())
    else:
        api.Backend.rpcclient.connect()
    print(' Done')

    managed_zones = {}
    from ipalib.plugins.dns import DNSName
    with codecs.open('subnet-map.cf', 'r', 'utf-8') as cf:
        FALLBACK_S, FALLBACK_T = cf.readline().rstrip().split(None, 1)
        FALLBACK_T = DNSName(FALLBACK_T.rstrip('.')+'.')
        for line in cf.readlines():
            s = line.rstrip().split(None, 1)
            managed_zones[s[0]] = DNSName(s[1].rstrip('.')+'.')
 
    print('Reading NetCenter...')
    hosts = dict()
    h4 = netcenterHosts(hosts, basicAuth, netgroup)
    h6 = netcenterHosts(hosts, basicAuth, netgroup, ipv6=True)
    print(' Done')

    for fqdn, ipaddrs in hosts.items():
        fqdn = fqdn.lstrip('+').strip('.')
        managed = False
        nnzone = None
        hn = None
        for mz in managed_zones:
            if fqdn.endswith('.'+mz):
                hn = unicode(fqdn[:-len(mz)-1])
                managed = True
                nnzone = managed_zones[mz]
                break
        if not managed and fqdn.endswith(FALLBACK_S):
            hn = fqdn[:-len(FALLBACK_S)-1]
            managed = True
            nnzone = FALLBACK_T
        if not hn:
            continue
        xmanaged = '* ' if managed else '  '
        print("{}{:20s}: {}, {}".format(xmanaged, fqdn, *ipaddrs))
        if nnzone:
            nhn = DNSName(hn)
            try:
                result = api.Command.dnsrecord_show(nnzone, nhn)['result']
            except ipalib.errors.NotFound:
                result = {}  # {'arecord': [], 'aaaarecord': []})
            if True: # len(result):
                arecord = result.get('arecord', ())
                aaaarecord = result.get('aaaarecord', ())
                kw = {}
                if ipaddrs[0] and ipaddrs[0] not in arecord:
                    kw['arecord'] = ipaddrs[0]
                if ipaddrs[1] and ipaddrs[1] not in aaaarecord:
                    kw['aaaarecord'] = ipaddrs[1]
                if kw:
                    try:
                        result2 = api.Command.dnsrecord_add(nnzone, nhn, **kw)
                    except ipalib.errors.EmptyModlist:
                        pass
                    except Exception as e:
                        print('*'*80)
                        print(e)
                        print(repr(ipaddrs))
                        print('*'*80)
            

if __name__ == '__main__':
    main()

