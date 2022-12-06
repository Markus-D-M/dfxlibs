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
import struct
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Dict, Generator, List
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Cipher import AES, ARC4, DES

if TYPE_CHECKING:
    import sqlite3


from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.registry.registryparser import get_guid
from dfxlibs.windows.helpers import filetime_to_dt
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_or, db_in
from dfxlibs.cli.environment import env

_logger = logging.getLogger(__name__)


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
