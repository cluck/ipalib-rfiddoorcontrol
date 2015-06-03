# -*- coding: utf-8 -*-

import datetime
import re

from ipalib import _
from ipalib import errors, output
from ipalib.parameters import Str
from ipalib.plugable import Registry
from ipalib.plugins import user
from ipalib.plugins.baseldap import (
        LDAPQuery,
        pkey_to_value,
        add_missing_object_class,
    )
from ipalib.plugins.internal import i18n_messages


# No other way to do this?:
i18n_messages.messages['actions'].update({
        'user_addrfid': _("Enable RFID"),
        'user_addrfid_confirm': _("Enable RFID?"),
        'user_addrfid_success': _("RFID Enabled"),
        'user_delrfid': _("Disable RFID"),
        'user_delrfid_confirm': _("Disable RFID?"),
        'user_delrfid_success': _("RFID Disabled"),
    })


user.user.takes_params += (
    Str('rfidkey*',
        cli_name='rfid_key',
        label=_('RFID Key'),
    ),
    Str('rfiddooraccess*',
        cli_name='rfid_door_access',
        label=_('RFID Door Access'),
    ),
)



register = Registry()


class AccessChangeManager(object):

    DISABLED = datetime.datetime(1, 1, 1, 0, 0, 0)
    FOREVER = datetime.datetime(9999, 12, 31, 23, 59, 59)

    def __init__(self, old_access, new_access):
        self._case = {}
        self._old = {}
        self._new = {}
        self._old.update(self._parse_accesses(old_access), case=True)
        self._new.update(self._parse_accesses(new_access))
        self.fill_gaps()
        self.known_accesses_mtime = 0
        self.reload_known_accesses()

    def reload_known_accesses(self):
        f = '/etc/ipa/doorlist.txt'
        mtime = os.stat(f).st_mtime
        doors = []
        if mtime <= self.known_accesses_mtime:
            return
        with codecs.open(f, 'r', 'utf-8') as fh:
            for door in fh:
                door = door.strip()
                if not door or door.startswith('#'):
                    continue
                if door not in doors:
                    doors.append(door)
        self.known_accesses = doors

    def _parse_accesses(self, acc_list, case=False):
        accesses = {}
        for acc_lel in acc_list or ():
            iacc_lel = acc_lel.lower().strip()
            if case and iacc_lel not in self._case:
                self._case[iacc_lel] = acc_lel
            acc_lel = acc_lel.replace(',', ';')
            for acc_t in acc_lel.split(';'):
                acc_t = acc_t.split(':', 1)
                acc = acc_t[0].lower().strip()
                if len(acc_t) == 2:
                    exc = acc_t[1].strip().upper()
                    if exc == 'DISABLED':
                        exc = '0001-01-01T00:00:00'
                    if 'T' not in exc:
                        exc += 'T00:00:00'
                else:
                    exc = '9999-12-31T23:59:59'
                try:
                    exc_dt = datetime.datetime.strptime(exc, '%Y-%m-%dT%H:%M:%S')   
                except:
                    if acc not in accesses:
                        accesses[acc] = acc_t[1]
                else:
                    if accesses.get(acc, exc_dt) <= exc_dt:
                        accesses[acc] = exc_dt
        for acc in accesses:
            yield acc, accesses[acc]

    def fill_gaps(self):
        self.reload_known_accesses()
        for acc in self._old:
            if acc not in self._new:
                self._new[acc] = self.DISABLED
        for acc in list(self._new):
            if self._new[acc] != self.DISABLED:
                continue
            if acc not in self.known_accesses:
                del self._new[acc]

    def get_access(self):
        for acc, exc in self._new.items():
            if exc == self.FOREVER:
                yield self._case.get(acc, acc)
            elif exc == self.DISABLED:
                s = '{0}: disabled'.format(acc)
                yield self._case.get(s, s)
            elif not isinstance(exc, datetime.datetime):
                s = '{0}:{1}'.format(acc, exc)
                yield self._case.get(s, s)
            elif (exc.hour, exc.minute, exc.second) == (0, 0, 0):
                s = '{0}: {1}'.format(acc, exc.strftime('%Y-%m-%d'))
                yield self._case.get(s, s)
            else:
                s = '{0}: {1}'.format(acc, exc.strftime('%Y-%m-%dT%H:%M:%S'))
                yield self._case.get(s, s)



def useradd_precallback(self, ldap, dn, entry, attrs_list, *keys, **options):
    try:
        objectclass = entry['objectclass']
    except KeyError:
        objectclass = entry['objectclass'] = []
        if 'objectclass' not in attrs_list:
            attrs_list.append('objectclass')
    if 'rfidkey' in entry or 'rfiddooraccess' in entry:
        if 'rfidDoorControl' not in objectclass:
            objectclass.append('rfidDoorControl')
        new_access = entry.get('rfiddooraccess', [])
        acm = AccessChangeManager([], new_access)
        entry['rfiddooraccess'] = list(acm.get_access())
    return dn

user.user_add.register_pre_callback(useradd_precallback)



def usermod_precallback(self, ldap, dn, entry, attrs_list, *keys, **options):
    if 'rfidkey' in entry or 'rfiddooraccess' in entry:
        entry.update(add_missing_object_class(ldap, 'rfidDoorControl', dn, update=False))
    # replace deleted rfiddooraccess with 'door: disabled' entries
    if 'rfiddooraccess' in entry:
        old_access = ldap.get_entry(dn, ['rfiddooraccess']).get('rfiddooraccess', ())
        new_access = entry.get('rfiddooraccess', [])
        acm = AccessChangeManager(old_access, new_access)
        entry['rfiddooraccess'] = list(acm.get_access())
    return dn

user.user_mod.register_pre_callback(usermod_precallback)


@register()
class user_addrfid(LDAPQuery):
    __doc__ = _('Add RFID control to users.')

    has_output = output.standard_value
    msg_summary = _('RFID enabled on "%(value)s"')

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        entry = self.obj.backend.get_entry(dn, ['objectclass'])

        if 'rfidDoorControl' not in entry['objectclass']:
            entry['objectclass'].append('rfidDoorControl')

        self.obj.backend.update_entry(entry)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )


@register()
class user_delrfid(LDAPQuery):
    __doc__ = _('Remove RFID control from users.')

    has_output = output.standard_value
    msg_summary = _('RFID disabled on "%(value)s"')

    def execute(self, *keys, **options):
        dn = self.obj.get_dn(*keys, **options)
        entry = self.obj.backend.get_entry(dn, ['objectclass', 'rfidKey', 'rfidDoorAccess'])

        while 'rfidDoorControl' in entry['objectclass']:
            entry['objectclass'].remove('rfidDoorControl')

        for att in ('rfidKey', 'rfidDoorAccess'):
            try:
                del entry[att]
            except KeyError:
                pass

        self.obj.backend.update_entry(entry)

        return dict(
            result=True,
            value=pkey_to_value(keys[0], options),
        )

