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
        #attrs2 = {}
        #for k, v in attrs.items():
        #    attrs2[k.lower()] = v
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

    def values(self, att, fmt='{0}'):
        vals = object.__getattribute__(self, '_LdapObject__attrs')[att]
        try:
            for val in vals:
                if isinstance(vals[0], basestring):
                    yield fmt.format(val.decode('utf-8').strip(), **object.__getattribute__(self, '_LdapObject__attrs'))
                else:
                    yield fmt.format(val.strip(), **object.__getattribute__(self, '_LdapObject__attrs'))
        except KeyError as e:
            raise AttributeError(str(e))

    def update(self, kw, att, toatt=None, fmt='{0}'):
        if toatt is None:
            toatt = att.lower()
        try:
            vals = list(self.values(att, fmt=fmt))
        except KeyError:
            if toatt in kw:
                del kw[toatt]
        else:
            ikw = map(lambda s: s.lower(), kw.get(toatt, ()))
            for val in vals:
                ival = val.lower()
                if not any(ival == v for v in ikw):
                    if toatt not in kw:
                        kw[toatt] = [val]
                    else:
                        kw[toatt].append(val)

    def setone(self, kw, att, toatt=None, default=None, fmt='{0}'):
        if toatt is None:
            toatt = att.lower()
        try:
            kw[toatt] = fmt.format(getattr(self, att), **object.__getattribute__(self, '_LdapObject__attrs'))
        except KeyError:
            if default:
                kw[toatt] = default


def ldapUsers(users, idoverrideusers, server, base):
    import ldap
    l = ldap.initialize('ldap://{0}:389'.format(server))
    #ret = l.search_s(base, ldap.SCOPE_SUBTREE, '(objectClass=inetOrgPerson)', [str('*'), str('objectClass')])
    ret = l.search_s(base, ldap.SCOPE_SUBTREE, '(objectClass=inetOrgPerson)')
    for dn, attrs in ret:
        user = LdapObject(dn, attrs)
        idoverride = LdapObject(
            'uid={0},cn=users,cn=compat,dc=soseth,dc=org'.format(user.uid), {
                #'cn': [user.cn], 
                'objectClass': ['posixAccount', 'top'],
                'gidNumber': ['10000'],
                'gecos': [user.cn],
                'uidNumber': [user.uidNumber],
                'loginShell': ['/bin/sh'],
                'homeDirectory': ['/home/{0}'.format(user.uid)],
                'uid': [user.uid],
             })
        idoverrideusers[user.uid] = idoverride
        users[user.uid] = user


def main(netgroup='adm-soseth'):

    print('Authenticating to FreeIPA...')
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
    idoverrideusers = dict()
    server = sys.argv[1]
    base = sys.argv[2]
    ldapUsers(users, idoverrideusers, server, base)
    print(' {0:d} Done'.format(len(users)))
    from ipapython.dn import DN

    for user in users.values():
        uid = user.uid
        if len(sys.argv) > 3 and uid != sys.argv[3]:
            continue
        try:
            result0 = api.Command.user_show(uid, all=True)
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

        user.update(kw, 'mail', 'edupersontargetedid', fmt='mail:{mail[0]}')
        user.update(kw, 'registeredAddress', 'edupersontargetedid', fmt='mail:{registeredAddress[0]}')
        user.setone(kw, 'street')
        user.setone(kw, 'l')
        user.setone(kw, 'postalCode')
        user.setone(kw, 'telephoneNumber')

        user.setone(kw, 'givenName', default=uid)
        user.setone(kw, 'sn')

        kwovr = {}
        userovr = idoverrideusers[user.uid]
        #userovr.setone(kwovr, 'cn')
        userovr.setone(kwovr, 'gecos')
        userovr.setone(kwovr, 'loginShell')
        userovr.setone(kwovr, 'homeDirectory')
        userovr.setone(kwovr, 'uidNumber')
        userovr.setone(kwovr, 'gidNumber')
        kwovr['uidnumber'] = int(kwovr['uidnumber'])
        kwovr['gidnumber'] = int(kwovr['gidnumber'])

        #print(user)
        #for k, v in kw.items():
        #    print("{0}: {1}".format(k, v))
        #continue
        try:
            try:
                result = api.Command.user_mod(uid,
                    uidnumber=user.uidNumber, gidnumber=user.gidNumber,
                    **kw)
                #result1 = api.Command.idoverrideuser_mod(uid, **kwovr)
                print('MOD', uid)
            except ipalib.errors.EmptyModlist as e:
                print('   ', uid)
                continue
            except ipalib.errors.NotFound as e:
                result = api.Command.user_add(uid,
                    #uidnumber=user.uidNumber, gidnumber=user.gidNumber,
                    #uidnumber=None, gidnumber=None,
                    gidnumber=10000,
                    **kw)
                print(result)
                #kwovr['ipaanchoruuid'] = result['result']['ipauniqueid'][0]
                #result1 = api.Command.idoverrideuser_add('xsos', result['result']['uid'][0], **kwovr)
                #result1 = api.Command.idoverrideuser_add('xsos', result['result']['ipauniqueid'][0], **kwovr)
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

