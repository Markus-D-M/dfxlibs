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

import sqlite3
from typing import Optional, Union, Dict, Generator, List
import struct
import logging
from datetime import datetime, timezone
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Cipher import AES, ARC4, DES

from dfxlibs.windows.registry.registryparser import get_guid
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like
from dfxlibs.windows.helpers import filetime_to_dt, bytes_to_sid


_logger = logging.getLogger(__name__)


class SECURITY(DefaultClass):
    def __init__(self, db_reg_cur: 'sqlite3.Cursor', boot_key: bytes):
        check_key = RegistryEntry.db_select_one(db_reg_cur, db_eq('parent_key', 'HKLM\\SECURITY'))
        if check_key is None:
            raise ValueError('no security hive found')
        self._db_reg_cur = db_reg_cur
        self._boot_key = boot_key
        self._lsa_keys: Optional[Dict[bytes, bytes]] = None
        self._is_pre_vista: Optional[bool] = None
        self._lsa_secrets: Optional[Dict[str, bytes]] = None
        self._domain_cache: Optional[DomainCache] = None
        self._machine_sid: Optional[str] = None
        self._domain_sid: Optional[str] = None

    @property
    def machine_sid(self):
        if self._machine_sid is None:
            self._machine_sid = 'unknown'
            reg_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                                   db_filter=db_and(
                                                                           db_eq(
                                                                               'parent_key',
                                                                               'HKLM\\SECURITY\\Policy'),
                                                                           db_eq('name', 'PolAcDmS'),
                                                                       ))
            if reg_entry:
                raw_sid = bytes.fromhex(reg_entry.get_real_value())
                self._machine_sid = bytes_to_sid(raw_sid)
        return self._machine_sid

    @property
    def domain_sid(self):
        if self._domain_sid is None:
            self._domain_sid = 'unknown'
            reg_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                                   db_filter=db_and(
                                                                           db_eq(
                                                                               'parent_key',
                                                                               'HKLM\\SECURITY\\Policy'),
                                                                           db_eq('name', 'PolPrDmS'),
                                                                       ))
            if reg_entry:
                raw_sid = bytes.fromhex(reg_entry.get_real_value())
                if raw_sid:
                    self._domain_sid = bytes_to_sid(raw_sid)
        return self._domain_sid


    @property
    def is_pre_vista(self):
        if self._is_pre_vista is None:
            self._get_lsa_keys()
        return self._is_pre_vista

    def get_user_infos(self, user_list=None):
        if user_list is None:
            user_list = dict()
        if self.domain_cache is None:
            return user_list
        domain_sid = self.domain_sid
        for nl_record in self.domain_cache.nl_records:
            sid = f'{domain_sid}-{nl_record.rid}'
            if sid not in user_list:
                user_list[sid] = {}

            user_list[sid]['User'] = f'{nl_record.domain_name}\\{nl_record.user}'
            if nl_record.upn:
                user_list[sid]['User Principal Name'] = nl_record.upn
            if nl_record.full_name:
                user_list[sid]['Full Name'] = nl_record.full_name
            if self.is_pre_vista:
                user_list[sid]['MS Cache V1'] = nl_record.ms_cache.hex()
                hashcat_mode = 1100
            else:
                user_list[sid]['MS Cache V2'] = nl_record.ms_cache.hex()
                hashcat_mode = 2100

            hashcat = {'mode': hashcat_mode, 'hash': nl_record.get_hashcat_row(self.domain_cache.iteration_count)}
            try:
                user_list[sid]['Hashcat'].append(hashcat)
            except KeyError:
                user_list[sid]['Hashcat'] = [hashcat]
        return user_list

    @property
    def domain_cache(self) -> 'DomainCache':
        if self._domain_cache is None:
            self._get_domain_cache()
        return self._domain_cache

    def _get_domain_cache(self):
        cache_entries: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                          db_filter=db_eq('parent_key',
                                                                                          'HKLM\\SECURITY\\Cache'))
        dcc_iteration_count = 10240
        nl_records = []
        nlkm_secret = self.get_lsa_secret('NL$KM')
        if nlkm_secret is None:
            _logger.info('no NL$KM secret')
            return
        for cache_entry in cache_entries:
            if cache_entry.name == "NL$Control":
                continue
            elif cache_entry.name == 'NL$IterationCount':
                value = cache_entry.get_real_value()
                dcc_iteration_count = value & 0xfffffc00 if value > 10240 else value * 1024

            cache_raw = cache_entry.get_real_value()
            if cache_raw[:2] == b'\0\0':
                # empty entry
                continue

            nl_record = NLRecord(data=cache_raw, nlkm_secret=nlkm_secret, is_pre_vista=self.is_pre_vista)
            nl_records.append(nl_record)
        self._domain_cache = DomainCache(nl_records, iteration_count=dcc_iteration_count)

    @property
    def lsa_keys(self) -> Dict[bytes, bytes]:
        if self._lsa_keys is None:
            self._get_lsa_keys()
        return self._lsa_keys

    def get_lsa_secret(self, name: str) -> Optional[bytes]:
        if self._lsa_secrets is None:
            self._get_lsa_secrets()
        try:
            return self._lsa_secrets[name]
        except KeyError:
            return None

    @staticmethod
    def _sha256_aes_decrypt_secret(sha256_key: bytes, sha256_data: bytes, ciphertext: bytes) -> bytes:
        key = SHA256.new(sha256_key + b''.join(sha256_data for _ in range(1000))).digest()
        aes = AES.new(key, mode=AES.MODE_ECB)
        decrypted = aes.decrypt(ciphertext)
        size, = struct.unpack_from('<I', decrypted)
        secret, = struct.unpack_from(f'{size}s', decrypted[16:])
        return secret

    def _get_lsa_keys(self):
        key_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                               db_filter=db_and(
                                                                   db_eq('parent_key', 'HKLM\\SECURITY\\Policy'),
                                                                   db_eq('name', 'PolEKList')))
        if not key_entry:
            key_entry: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                                   db_filter=db_and(
                                                                       db_eq('parent_key', 'HKLM\\SECURITY\\Policy'),
                                                                       db_eq('name', 'PolSecretEncryptionKey')))
            if not key_entry:
                _logger.warning('unable to retrieve lsa key')
            self._is_pre_vista = True
            lsa_key_raw = bytes.fromhex(key_entry.get_real_value())
            data, key = lsa_key_raw[0x0c:0x3c], lsa_key_raw[0x3c:0x4c]

            key = MD5.new(self._boot_key + b''.join(key for _ in range(1000))).digest()
            rc4 = ARC4.new(key)
            secret = rc4.decrypt(data)[0x10: 0x20]
            self._lsa_keys = {b'legacy': secret}
            return

        self._is_pre_vista = False
        lsa_key_raw = bytes.fromhex(key_entry.get_real_value())
        version, key_id, algo, flags, data = \
            lsa_key_raw[:4], lsa_key_raw[4:20], lsa_key_raw[20:24], lsa_key_raw[24:28], lsa_key_raw[28:]
        secret = self._sha256_aes_decrypt_secret(self._boot_key, data[:32], data[32:])

        key_id = secret[28:44]
        lsa_secret = secret[52:84]
        self._lsa_keys = {key_id: lsa_secret}

    @staticmethod
    def _expand_des_key(key: bytes, rounds: int, add_odd_parity: bool = True) -> List[bytes]:
        keys = []
        j = 0
        for i in range(rounds):
            round_key = key[j:j + 7]
            # split to 8 7bit values and fill eigth bit with odd parity
            qs, = struct.unpack('>Q', b'\0' + round_key)  # convert to 64bit integer (pad high significant bits with \0)
            bit_str = f'{qs:056b}'  # convert to 56 0/1 bit string
            key_bytes = [
                int(bit_str[i:i + 7] + ('1' if add_odd_parity and bit_str[i:i + 7].count('1') % 2 == 0 else '0'), 2)
                for i in range(0, len(bit_str), 7)]  # split every 7 bits and append an odd parity bit
            keys.append(bytes(key_bytes))  # convert the resulting 8 one byte values to bytes and append es round_key

            j += 7
            if len(key[j:j + 7]) < 7:
                j = len(key[j:j + 7])
        return keys

    def _get_lsa_secrets(self):
        self._lsa_secrets = {}
        _ = self.lsa_keys
        secret_entries: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                           db_filter=db_and(
                                                                              db_like('parent_key',
                                                                                      'HKLM\\SECURITY\\'
                                                                                      'Policy\\Secrets\\%'),
                                                                              db_eq('name', 'CurrVal')))
        for secret_entry in secret_entries:
            _, secret_name = secret_entry.parent_key.rsplit('\\', 1)
            try:
                nlkm_key_raw = bytes.fromhex(secret_entry.get_real_value())
            except ValueError:
                continue
            if self.is_pre_vista:
                data = nlkm_key_raw[0x0c:]
                key = self.lsa_keys[b'legacy']

                rounds = len(data) // 8
                keys = self._expand_des_key(key, rounds)
                plain = b''
                for i in range(rounds):
                    plain += DES.new(keys[i], DES.MODE_ECB).decrypt(data[i * 8:i * 8 + 8])

                data_len, = struct.unpack_from('<I', plain)
                self._lsa_secrets[secret_name] = plain[8:8 + data_len]
            else:
                version, key_id, algo, flags, data = \
                    nlkm_key_raw[:4], nlkm_key_raw[4:20], nlkm_key_raw[20:24], nlkm_key_raw[24:28], nlkm_key_raw[28:]
                try:
                    lsa_secret = self.lsa_keys[key_id]
                except KeyError:
                    _logger.warning(f'cannot retrieve lsa key {get_guid(key_id)} for secret {secret_name}')
                    continue
                secret = self._sha256_aes_decrypt_secret(lsa_secret, data[:32], data[32:])
                self._lsa_secrets[secret_name] = secret


class DomainCache(DefaultClass):
    def __init__(self, nl_records: List['NLRecord'] = None, iteration_count: int = 10240):
        self.nl_records = nl_records if nl_records is not None else []
        self.iteration_count = iteration_count


class NLRecord(DefaultClass):
    def __init__(self, data: bytes, nlkm_secret: bytes, is_pre_vista: bool):
        self._is_pre_vista = is_pre_vista
        self._len_user, self._len_domain_name, self._len_effective_name, self._len_full_name = \
            struct.unpack_from('<4H', data[0:])
        self._len_logon_script_name, self._len_profile_path, self._len_home_directory, \
            self._len_home_directory_drive = struct.unpack_from('<4H', data[8:])
        self.rid, self.primary_group_id, self.group_count, self._len_logon_domain_name = \
            struct.unpack_from('<3IH', data[16:])
        self.last_write, self.revision, self.count_sid, self.flags = struct.unpack_from('<Q3I', data[32:])
        self.last_write = filetime_to_dt(self.last_write)
        self._len_logon_package, self._len_dns_domain_name, self._len_upn = \
            struct.unpack_from('<IHH', data[56:])

        iv = data[64:80]
        enc_data = data[96:]

        if is_pre_vista:
            key = HMAC.new(nlkm_secret, iv).digest()
            rc4 = ARC4.new(key)
            decrypted_data = rc4.encrypt(enc_data)
        else:
            if len(enc_data) % 16:
                # pad to 16 bytes boundaries
                enc_data += b'\0' * (16 - (len(enc_data) % 16))
            aes = AES.new(nlkm_secret[:16], iv=iv, mode=AES.MODE_CBC)
            decrypted_data = aes.decrypt(enc_data)

        # 4 byte aligned
        self.ms_cache = decrypted_data[:16]
        offset = 0x48
        try:
            self.user = decrypted_data[offset:offset + self._len_user].decode('utf16')
        except UnicodeDecodeError:
            self.user = ''
        offset += self._len_user
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.domain_name = decrypted_data[offset:offset + self._len_domain_name].decode('utf16')
        except UnicodeDecodeError:
            self.domain_name = ''
        offset += self._len_domain_name
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.dns_domain_name = decrypted_data[offset:offset + self._len_dns_domain_name].decode('utf16')
        except UnicodeDecodeError:
            self.dns_domain_name = ''
        offset += self._len_dns_domain_name
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.upn = decrypted_data[offset:offset + self._len_upn].decode('utf16')
        except UnicodeDecodeError:
            self.upn = ''
        offset += self._len_upn
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.effective_name = decrypted_data[offset:offset + self._len_effective_name].decode('utf16')
        except UnicodeDecodeError:
            self.effective_name = ''
        offset += self._len_effective_name
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.full_name = decrypted_data[offset:offset + self._len_full_name].decode('utf16')
        except UnicodeDecodeError:
            self.full_name = ''
        offset += self._len_full_name
        if offset % 4:
            offset += (4 - (offset % 4))
        try:
            self.home_directory = decrypted_data[offset:offset + self._len_home_directory].decode('utf16')
        except UnicodeDecodeError:
            self.home_directory = ''
        offset += self._len_home_directory
        if offset % 4:
            offset += (4 - (offset % 4))
        self.home_directory_drive = decrypted_data[offset:offset + self._len_home_directory_drive].decode('utf16')
        offset += self._len_home_directory_drive
        if offset % 4:
            offset += (4 - (offset % 4))

    def get_hashcat_row(self, iteration_count: int = 10240):
        if self._is_pre_vista:
            return f'{self.ms_cache.hex()}:{self.user}'
        else:
            return f'$DCC2${iteration_count}#{self.user}#{self.ms_cache.hex()}'
