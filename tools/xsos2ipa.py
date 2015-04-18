#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import unicode_literals, print_function

import os
import pwd
import codecs
import sys
import getpass
import httplib2
import base64
import traceback
import pprint

from lxml import objectify
from lxml import etree

from ipaserver.plugins.ldap2 import ldap2
from ipalib import api
import ipalib.errors


class LdapObject(object):

    def __init__(self, dn, attrs):
        object.__setattr__(self, '_LdapObject__attrs', attrs)
        object.__setattr__(self, 'dn', dn)

    def __getattr__(self, att):
        vals = object.__getattribute__(self, '_LdapObject__attrs')[att]
        if len(vals) != 1:
            raise ValueError('not exactly one value')
        if isinstance(vals[0], basestring):
            return vals[0].decode('utf-8').strip()
        return vals[0].strip()

    def __repr__(self):
        atts = object.__getattribute__(self, '_LdapObject__attrs')
        s = ''.join( ( '{0}={1} '.format(k, ','.join(atts[k])) for k in atts ) )
        return '<{0} {1}>'.format(self.dn, s.rstrip(' '))

    def values(self, att):
        vals = object.__getattribute__(self, '_LdapObject__attrs')[att]
        for val in vals:
            if isinstance(vals[0], basestring):
                yield val.decode('utf-8').strip()
            else:
                yield val.strip()

    def update(self, kw, att, toatt=None):
        if toatt is None:
            toatt = att.lower()
        try:
            vals = list(self.values(att))
        except KeyError:
            if toatt in kw:
                del kw[toatt]
        else:
            ikw = map(lambda s: s.lower(), kw.get(toatt, ()))
            for val in vals:
                ival = val.lower()
                if any(ival == v for v in ikw):
                    kw[toatt].append(val)

    def setone(self, kw, att, toatt=None, default=None):
        if toatt is None:
            toatt = att.lower()
        try:
            kw[toatt] = getattr(self, att)
        except KeyError:
            if default:
                kw[toatt] = default


def ldapUsers(users, server, base):
    import ldap
    l = ldap.initialize('ldap://{0}:389'.format(server))
    ret = l.search_s(base, ldap.SCOPE_SUBTREE, '(objectClass=inetOrgPerson)')
    for dn, attrs in ret:
        user = LdapObject(dn, attrs)
        users[user.uid] = user


def main(netgroup='adm-soseth'):

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

    ## sys.setrecursionlimit(20)
    print('Reading LDAP...')
    users = dict()
    server = sys.argv[1]
    base = sys.argv[2]
    ldapUsers(users, server, base)
    print(' {0:d} Done'.format(len(users)))
    from ipapython.dn import DN

    for user in users.values():
        uid = user.uid
        if len(sys.argv) > 3 and uid != sys.argv[3]:
            continue
        try:
            result0 = api.Command.user_show(uid)
            memberof_group = result0['result'].get('memberof_group', ())
            for g_protected in ('admins', 'trust_admins', 'editors'):
                if g_protected in memberof_group:
                    print('Skipping {0} user {1}'.format(g_protected, uid))
                    uid = None
        except ipalib.errors.NotFound:
            pass
        if uid is None:
            continue
        kw = {}
        user.update(kw, 'mail')
        user.update(kw, 'mobile')
        user.setone(kw, 'loginShell')
        user.setone(kw, 'homeDirectory')
        user.update(kw, 'rfidKey')
        user.update(kw, 'rfidDoorAccess')

        user.setone(kw, 'registeredAddress', 'mail')
        user.setone(kw, 'street')
        user.setone(kw, 'l')
        user.setone(kw, 'postalCode')
        user.setone(kw, 'telephoneNumber')

        user.setone(kw, 'givenName', default=uid)
        user.setone(kw, 'sn')
        try:
            try:
                result = api.Command.user_mod(uid,
                    uidnumber=user.uidNumber, gidnumber=user.gidNumber,
                    **kw)
                print('MOD', uid)
            except ipalib.errors.EmptyModlist as e:
                print('   ', uid)
                continue
            except ipalib.errors.NotFound as e:
                result = api.Command.user_add(uid,
                    uidnumber=user.uidNumber, gidnumber=user.gidNumber,
                    **kw)
                print('ADD', uid)
        except Exception as e:
            print('-----------')
            traceback.print_exc()
            print()
            print(repr(user))
            print()
            result2 = api.Command.user_show(uid)
            print(repr(result2['result']))
            print()
            print('EEE', uid)
        #break


if __name__ == '__main__':
    main()

