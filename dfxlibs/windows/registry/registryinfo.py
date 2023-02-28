"""
    Copyright 2022 Markus D (mar.d@gmx.net)

    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

        https://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
"""

import logging
import re
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Generator, List
from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult

if TYPE_CHECKING:
    import sqlite3


from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.helpers import filetime_to_dt
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.partition import Partition
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_or, db_in
from dfxlibs.cli.environment import env

_logger = logging.getLogger(__name__)


def _dn2cn(dn: str) -> str:
    parts = dn.split(',')
    for part in parts:
        part = part.strip()
        if part.lower().startswith('cn='):
            return part[3:].strip()
    return dn


def get_autoruns(db_file_cur: 'sqlite3.Cursor' = None, partition: Partition = None):
    autoruns: List[Autorun] = env['globals']['software'].get_autoruns()
    autoruns = env['globals']['user'].get_autoruns(autoruns)
    result = []
    for ar in autoruns:
        p_dir = ar.parent_dir.replace('\\', '/')
        if p_dir[1:3] == ':/':
            p_dir = p_dir[2:]
        p_dir = re.sub(r'%[a-z0-9_-]+?%', '%', p_dir, flags=re.I)
        exe_files: Generator['File'] = File.db_select(db_file_cur, db_filter=db_and(db_like('parent_folder', p_dir),
                                                                                    db_like('name', ar.exe_name),
                                                                                    db_eq('source', 'filesystem'),
                                                                                    db_eq('allocated', 1)))
        exe_list = [e for e in exe_files]
        if len(exe_list) == 0:
            # file not found
            pass
        elif len(exe_list) > 1:
            # multiple candidates found
            pass
        else:
            exe_list[0].open(partition)
            pefile = SignedPEFile(exe_list[0])
            status, msg = pefile.explain_verify()
            if status == AuthenticodeVerificationResult.NOT_SIGNED:
                ar.signature = 'not signed'
            elif status == AuthenticodeVerificationResult.OK:
                ar.signature = 'signed'
                for signed_data in pefile.signed_datas:
                    certs = {cert.serial_number: cert for cert in signed_data.certificates}
                    ar.signer += ('\n' if ar.signer else '') + \
                        _dn2cn(certs[signed_data.signer_info.serial_number].subject.dn)
                    if signed_data.signer_info.countersigner:
                        if hasattr(signed_data.signer_info.countersigner, 'certificates'):
                            certs.update({cert.serial_number: cert
                                          for cert in signed_data.signer_info.countersigner.certificates})
                        try:
                            ar.countersigner += ('\n' if ar.countersigner else '') + \
                                _dn2cn(certs[signed_data.signer_info.countersigner.serial_number].subject.dn)
                        except AttributeError:
                            ar.countersigner += ('\n' if ar.countersigner else '') + \
                                _dn2cn(
                                    certs[signed_data.signer_info.countersigner.signer_info.serial_number].subject.dn)
                        ar.signing_timestamp += ('\n' if ar.signing_timestamp else '') + \
                            signed_data.signer_info.countersigner.signing_time.isoformat()
            else:
                ar.signature = 'error: ' + str(msg)

        result.append(ar)
    return result


def get_user(db_reg_cur: 'sqlite3.Cursor') -> Dict[str, Dict[str, str]]:

    user_list = user_list = env['globals']['software'].get_user_infos()
    user_list = env['globals']['sam'].get_user_infos(user_list)
    user_list = env['globals']['security'].get_user_infos(user_list)
    user_list = env['globals']['user'].get_user_infos(user_list)

    return user_list


def get_network_devices(db_reg_cur: 'sqlite3.Cursor') -> Dict[str, Dict[str, str]]:
    current_control_set = env['globals']['system'].current_control_set
    reg_entries: Generator[RegistryEntry] = RegistryEntry.db_select(db_reg_cur,
                                                                    db_filter=db_and(
                                                                        db_like(
                                                                            'parent_key',
                                                                            f'HKLM\\SYSTEM\\'
                                                                            f'ControlSet{current_control_set:03d}\\'
                                                                            f'Control\\Class\\'
                                                                            f'{{4d36e972-e325-11ce-bfc1-'
                                                                            f'08002be10318}}\\%'),
                                                                        db_or(
                                                                            db_eq('name', 'DriverDesc'),
                                                                            db_eq('name', 'NetCfgInstanceId')
                                                                        )))

    adapters = dict()
    for reg_entry in reg_entries:
        _, number = reg_entry.parent_key.rsplit('\\', 1)
        if number not in adapters:
            adapters[number] = {}
        adapters[number][reg_entry.name] = reg_entry.get_real_value()
    adapters = {adapters[number]['NetCfgInstanceId']: {'Name': adapters[number]['DriverDesc']}
                for number in adapters
                if 'DriverDesc' in adapters[number] and 'NetCfgInstanceId' in adapters[number]}

    for adapter_guid in adapters:
        dev_infos: Generator[RegistryEntry] = RegistryEntry.db_select(db_reg_cur,
                                                                      db_filter=db_and(
                                                                          db_like(
                                                                              'parent_key',
                                                                              f'HKLM\\SYSTEM\\'
                                                                              f'ControlSet{current_control_set:03d}\\'
                                                                              f'Services\\Tcpip\\Parameters\\'
                                                                              f'Interfaces\\{adapter_guid}'),
                                                                          db_in('name', ['DhcpIPAddress', 'EnableDHCP',
                                                                                         'DhcpDefaultGateway',
                                                                                         'DefaultGateway',
                                                                                         'DhcpSubnetMask',
                                                                                         'IPAddress', 'SubnetMask'])
                                                                      ))
        for dev_info in dev_infos:
            if dev_info.name == 'EnableDHCP':
                adapters[adapter_guid]['DHCP'] = bool(dev_info.get_real_value())
            elif dev_info.name in ['DhcpIPAddress', 'IPAddress']:
                adapters[adapter_guid]['IPAddress'] = dev_info.get_real_value()
                if type(adapters[adapter_guid]['IPAddress']) is list:
                    adapters[adapter_guid]['IPAddress'] = ', '.join(
                        [x for x in adapters[adapter_guid]['IPAddress'] if x])
            elif dev_info.name in ['DhcpSubnetMask', 'SubnetMask']:
                adapters[adapter_guid]['SubnetMask'] = dev_info.get_real_value()
                if type(adapters[adapter_guid]['SubnetMask']) is list:
                    adapters[adapter_guid]['SubnetMask'] = ', '.join(
                        [x for x in adapters[adapter_guid]['SubnetMask'] if x])
            elif dev_info.name in ['DhcpDefaultGateway', 'DefaultGateway']:
                adapters[adapter_guid]['DefaultGateway'] = dev_info.get_real_value()
                if type(adapters[adapter_guid]['DefaultGateway']) is list:
                    adapters[adapter_guid]['DefaultGateway'] = ', '.join(
                        [x for x in adapters[adapter_guid]['DefaultGateway'] if x])

    return adapters


def get_os_infos(db_reg_cur: 'sqlite3.Cursor') -> Dict[str, any]:
    result = {}
    current_control_set = env['globals']['system'].current_control_set
    information_entries = [
        {'target_name': 'Product Name', 'value': 'ProductName',
         'parent_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'},
        {'target_name': 'Registered Owner', 'value': 'RegisteredOwner',
         'parent_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'},
        {'target_name': 'System Root', 'value': 'SystemRoot',
         'parent_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'},
        {'target_name': 'Current Build', 'value': 'CurrentBuild',
         'parent_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'},
        {'target_name': 'Install Time', 'value': 'InstallTime', 'WindowsTime': True,
         'parent_key': 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'},
    ]
    if current_control_set != -1:
        information_entries.extend([
            {'target_name': 'Computer Name', 'value': 'ComputerName',
             'parent_key': f'HKLM\\SYSTEM\\ControlSet{current_control_set:03d}\\Control\\ComputerName\\ComputerName'},
            {'target_name': 'Domain', 'value': 'Domain',
             'parent_key': f'HKLM\\SYSTEM\\ControlSet{current_control_set:03d}\\Services\\Tcpip\\Parameters'},
        ])
    for information_entry in information_entries:
        reg_entry: RegistryEntry = RegistryEntry.db_select_one(db_reg_cur, db_filter=db_and(
            db_eq('parent_key', information_entry['parent_key']),
            db_eq('name', information_entry['value'])
        ))
        if reg_entry:
            if 'WindowsTime' in information_entry:
                result[information_entry['target_name']] = filetime_to_dt(reg_entry.get_real_value()).isoformat()
            else:
                result[information_entry['target_name']] = reg_entry.get_real_value()

    return result


class Autorun(DefaultClass):
    table_header = ['Description', 'Executable', 'Directory', 'Commandline',
                    'Type', 'Additional Info', 'User', 'Created',
                    'Signature', 'Signer', 'Countersigner', 'Signing Timestamp',
                    'Source']

    def to_list(self):
        return [self.description, self.exe_name, self.parent_dir, self.commandline,
                self.type, self.add_info, self.user, self.created,
                self.signature, self.signer, self.countersigner, self.signing_timestamp,
                self.source]

    def __init__(self, description: str = '', commandline: str = '', source: str = '', ar_type: str = '',
                 user: str = ''):
        self.commandline = ''
        self.source = source
        self.parent_dir = ''
        self.exe_name = ''
        self.parameters = ''
        self.add_info = ''
        self.type = ar_type
        self.user = user
        self.description = description
        self.created = ''
        self.signature = ''
        self.signer = ''
        self.countersigner = ''
        self.signing_timestamp = ''
        if commandline:
            self.add_commandline(commandline)

    @staticmethod
    def _tokenize_commandline(commandline: str) -> List[str]:
        in_parenthesis = False
        escape_next = False
        cur_token = ''
        token = []
        for char in commandline:
            if escape_next:
                cur_token += char
                escape_next = False
            elif char in ["'", '"']:
                if in_parenthesis:
                    if cur_token:
                        token.append(cur_token)
                        cur_token = ''
                in_parenthesis = not in_parenthesis
            elif in_parenthesis:
                cur_token += char
            elif char == " ":
                if cur_token:
                    token.append(cur_token)
                cur_token = ''
            else:
                cur_token += char
        if cur_token:
            token.append(cur_token)

        # check if first tokens should be merged (e.g. space in folder) - this method only merge one space per subfolder
        # which is sufficent for most cases
        if len(token) > 0 and " " not in token[0]:
            # if there is a space in token[0] there is no need for merging (tokenization via parenthesis)
            while len(token) > 1:
                if " " in token[1]:
                    # only merge token, if there is no space in them (spaces only occurs while using parenthesis for
                    # tokenization)
                    break
                if "\\" in token[0][1:-1] and '\\' in token[1][1:-1] and not any([char in token[1] for char in '*/:<>?|']):
                    # merge if backslashes in the first two tokens not as first or last char and token[1] does not contain
                    # any forbidden chars
                    token = [token[0] + " " + token[1], *token[2:]]
                else:
                    # else merging finished
                    break

        return token

    def add_commandline(self, commandline: str):
        self.commandline = commandline
        print (commandline, self._tokenize_commandline(commandline))
        parts = commandline.split(' ')
        fullpath = ''
        while '.' not in fullpath[:-1] and len(parts) > 0:
            fullpath += (' ' + parts.pop(0))
        params = ' '.join(parts)
        fullpath = fullpath.strip(' "')

        if '\\' in fullpath:
            path, exe = fullpath.rsplit('\\', maxsplit=1)
        else:
            path = ''
            exe = fullpath
        self.parent_dir = path
        self.exe_name = exe
        self.parameters = params
