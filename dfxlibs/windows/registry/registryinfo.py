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
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

if TYPE_CHECKING:
    import sqlite3

from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.registry.registryparser import get_guid
from dfxlibs.windows.helpers import filetime_to_dt
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_or, db_in

_logger = logging.getLogger(__name__)


def get_network_devices(db_reg_cur: 'sqlite3.Cursor') -> Dict[str, Dict[str, str]]:
    current_control_set = get_current_control_set(db_reg_cur)
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
    current_control_set = get_current_control_set(db_reg_cur)
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


def get_current_control_set(db_reg_cur: 'sqlite3.Cursor') -> int:
    reg_entry: RegistryEntry = RegistryEntry.db_select_one(db_reg_cur,
                                                           db_filter=db_and(
                                                                db_eq('parent_key', 'HKLM\\SYSTEM\\Select'),
                                                                db_eq('name', 'Current')))
    if reg_entry:
        return reg_entry.get_real_value()
    else:
        return -1


def get_boot_key(db_reg_cur: 'sqlite3.Cursor') -> bytes:
    current_control_set = get_current_control_set(db_reg_cur)
    if current_control_set == -1:
        return b''

    bootkey_scrambled = ''
    for key_name in ['JD', 'Skew1', 'GBG', 'Data']:
        key_entry: RegistryEntry = RegistryEntry.db_select_one(db_reg_cur,
                                                               db_filter=db_and(
                                                                   db_eq('parent_key',
                                                                         'HKLM\\SYSTEM\\ControlSet'
                                                                         f'{current_control_set:03d}'
                                                                         '\\Control\\Lsa'),
                                                                   db_eq('name', key_name)))
        bootkey_scrambled += key_entry.classname

    bootkey_scrambled = bytes.fromhex(bootkey_scrambled)
    bootkey_perm_matrix = [0x8, 0x5, 0x4, 0x2, 0xb, 0x9, 0xd, 0x3, 0x0, 0x6, 0x1, 0xc, 0xe, 0xa, 0xf, 0x7]
    bootkey = bytes([bootkey_scrambled[bootkey_perm_matrix[i]] for i in range(len(bootkey_scrambled))])
    return bootkey


def sha256_aes_decrypt_secret(sha256_key: bytes, sha256_data: bytes, ciphertext: bytes) -> bytes:
    key = SHA256.new(sha256_key + b''.join(sha256_data for _ in range(1000))).digest()
    aes = AES.new(key, mode=AES.MODE_ECB)
    decrypted = aes.decrypt(ciphertext)
    size, = struct.unpack_from('<I', decrypted)
    secret, = struct.unpack_from(f'{size}s', decrypted[16:])
    return secret


def get_lsa_keys(db_reg_cur: 'sqlite3.Cursor', boot_key: bytes) -> Dict[bytes, bytes]:
    key_entry: RegistryEntry = RegistryEntry.db_select_one(db_reg_cur,
                                                           db_filter=db_and(
                                                               db_eq('parent_key', 'HKLM\\SECURITY\\Policy'),
                                                               db_eq('name', 'PolEKList')))
    if not key_entry:
        # maybe not Vista+
        return {}
    lsa_key_raw = bytes.fromhex(key_entry.get_real_value())
    version, key_id, algo, flags, data = lsa_key_raw[:4], lsa_key_raw[4:20], lsa_key_raw[20:24], lsa_key_raw[24:28], \
                                         lsa_key_raw[28:]
    secret = sha256_aes_decrypt_secret(boot_key, data[:32], data[32:])

    key_id = secret[28:44]
    lsa_secret = secret[52:84]
    return {key_id: lsa_secret}


def get_lsa_secrets(db_reg_cur: 'sqlite3.Cursor') -> Dict[str, bytes]:
    lsa_keys = get_lsa_keys(db_reg_cur, get_boot_key(db_reg_cur))
    secrets = {}

    secret_entries: Generator[RegistryEntry] = RegistryEntry.db_select(db_reg_cur,
                                                                       db_filter=db_and(
                                                                          db_like('parent_key', 'HKLM\\SECURITY\\Policy\\Secrets\\%'),
                                                                          db_eq('name', 'CurrVal')))
    for secret_entry in secret_entries:
        _, secret_name = secret_entry.parent_key.rsplit('\\', 1)
        try:
            nlkm_key_raw = bytes.fromhex(secret_entry.get_real_value())
        except ValueError:
            continue
        version, key_id, algo, flags, data = nlkm_key_raw[:4], nlkm_key_raw[4:20], nlkm_key_raw[20:24], \
                                             nlkm_key_raw[24:28], nlkm_key_raw[28:]
        try:
            lsa_secret = lsa_keys[key_id]
        except IndexError:
            _logger.warning(f'cannot retrieve lsa key {get_guid(key_id)}')
            continue
        secret = sha256_aes_decrypt_secret(lsa_secret, data[:32], data[32:])
        secrets[secret_name] = secret
    return secrets


def get_domain_cache(db_reg_cur: 'sqlite3.Cursor', nlkm_secret: bytes) -> 'DomainCache':
    cache_entries: Generator[RegistryEntry] = RegistryEntry.db_select(db_reg_cur,
                                                                      db_filter=db_eq('parent_key',
                                                                                      'HKLM\\SECURITY\\Cache'))
    nl_records = []
    iteration_count = 10240
    for cache_entry in cache_entries:
        if cache_entry.name == "NL$Control":
            continue
        elif cache_entry.name == 'NL$IterationCount':
            value = cache_entry.get_real_value()
            iteration_count = value & 0xfffffc00 if value > 10240 else value * 1024

        cache_raw = cache_entry.get_real_value()
        if cache_raw[:2] == b'\0\0':
            # empty entry
            continue

        iv = cache_raw[64:80]
        enc_data = cache_raw[96:]

        if len(enc_data) % 16:
            # pad to 16 bytes boundaries
            enc_data += b'\0'*(16-(len(enc_data) % 16))
        aes = AES.new(nlkm_secret[:16], iv=iv, mode=AES.MODE_CBC)
        decrypted = aes.decrypt(enc_data)
        nl_record = NLRecord(metadata=cache_raw[:64], decrypted_data=decrypted)
        nl_records.append(nl_record)
    return DomainCache(nl_records, iteration_count=iteration_count)


class DomainCache(DefaultClass):
    def __init__(self, nl_records: List['NLRecord'] = None, iteration_count: int = 10240):
        self.nl_records = nl_records if nl_records is not None else []
        self.iteration_count = iteration_count


class NLRecord(DefaultClass):
    def __init__(self, metadata: bytes = None, decrypted_data: bytes = None):
        self._len_user = -1
        self._len_domain_name = -1
        self._len_effective_name = -1
        self._len_full_name = -1
        self._len_logon_script_name = -1
        self._len_profile_path = -1
        self._len_home_directory = -1
        self._len_home_directory_drive = -1
        self.user_id = -1
        self.primary_group_id = -1
        self.group_count = -1
        self._len_logon_domain_name = -1
        self.last_write = datetime.fromtimestamp(0, tz=timezone.utc)
        self.revision = -1
        self.count_sid = -1
        self.flags = -1
        self._len_logon_package = -1
        self._len_dns_domain_name = -1
        self._len_upn = -1
        if metadata:
            self._len_user, self._len_domain_name, self._len_effective_name, self._len_full_name = \
                struct.unpack_from('<4H', metadata[0:])
            self._len_logon_script_name, self._len_profile_path, self._len_home_directory, \
                self._len_home_directory_drive = struct.unpack_from('<4H', metadata[8:])
            self.user_id, self.primary_group_id, self.group_count, self._len_logon_domain_name = \
                struct.unpack_from('<3IH', metadata[16:])
            self.last_write, self.revision, self.count_sid, self.flags = struct.unpack_from('<Q3I', metadata[32:])
            self.last_write = filetime_to_dt(self.last_write)
            self._len_logon_package, self._len_dns_domain_name, self._len_upn = \
                struct.unpack_from('<IHH', metadata[56:])
        self.ms_cache_v2 = b''
        self.user = ''
        self.domain_name = ''
        self.dns_domain_name = ''
        self.upn = ''
        self.effective_name = ''
        self.full_name = ''
        self.home_directory = ''
        self.home_directory_drive = ''
        if decrypted_data:
            # 4 byte aligned
            self.ms_cache_v2 = decrypted_data[:16]
            offset = 0x48
            self.user = decrypted_data[offset:offset + self._len_user].decode('utf16')
            offset += self._len_user
            if offset % 4:
                offset += (4 - (offset % 4))
            self.domain_name = decrypted_data[offset:offset + self._len_domain_name].decode('utf16')
            offset += self._len_domain_name
            if offset % 4:
                offset += (4 - (offset % 4))
            self.dns_domain_name = decrypted_data[offset:offset + self._len_dns_domain_name].decode('utf16')
            offset += self._len_dns_domain_name
            if offset % 4:
                offset += (4 - (offset % 4))
            self.upn = decrypted_data[offset:offset + self._len_upn].decode('utf16')
            offset += self._len_upn
            if offset % 4:
                offset += (4 - (offset % 4))
            self.effective_name = decrypted_data[offset:offset + self._len_effective_name].decode('utf16')
            offset += self._len_effective_name
            if offset % 4:
                offset += (4 - (offset % 4))
            self.full_name = decrypted_data[offset:offset + self._len_full_name].decode('utf16')
            offset += self._len_full_name
            if offset % 4:
                offset += (4 - (offset % 4))
            self.home_directory = decrypted_data[offset:offset + self._len_home_directory].decode('utf16')
            offset += self._len_home_directory
            if offset % 4:
                offset += (4 - (offset % 4))
            self.home_directory_drive = decrypted_data[offset:offset + self._len_home_directory_drive].decode('utf16')
            offset += self._len_home_directory_drive
            if offset % 4:
                offset += (4 - (offset % 4))

    def get_hashcat_row(self, iteration_count: int = 10240):
        return f'$DCC2${iteration_count}#{self.user}#{self.ms_cache_v2.hex()}'
