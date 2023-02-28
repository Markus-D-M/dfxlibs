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
from typing import Optional, Generator
from Crypto.Hash import SHA256, MD5, HMAC
from Crypto.Cipher import AES, ARC4, DES
import struct
import logging
from datetime import datetime, timezone

from dfxlibs.windows.helpers import filetime_to_dt
from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_in

_logger = logging.getLogger(__name__)


class SAM(DefaultClass):
    def __init__(self, db_reg_cur: 'sqlite3.Cursor', boot_key: bytes):
        check_key = RegistryEntry.db_select_one(db_reg_cur, db_eq('parent_key', 'HKLM\\SAM'))
        if check_key is None:
            raise ValueError('no sam hive found')
        self._db_reg_cur = db_reg_cur
        self._boot_key = boot_key
        self._hashed_boot_key: Optional[bytes] = None
        self._machine_sid: Optional[str] = None

    @property
    def machine_sid(self):
        if self._machine_sid is None:
            sam_account_v: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                                       db_filter=db_and(
                                                                           db_eq(
                                                                               'parent_key',
                                                                               'HKLM\\SAM\\SAM\\Domains\\Account'),
                                                                           db_eq('name', 'V'),
                                                                       ))
            if sam_account_v:
                sid_data = struct.unpack_from('3I', sam_account_v.get_real_value()[-12:])
                self._machine_sid = 'S-1-5-21-' + '-'.join([str(s) for s in sid_data])
            else:
                self._machine_sid = 'unknown'
                _logger.warning('unabble to retrieve machine sid')
        return self._machine_sid

    @property
    def hashed_boot_key(self) -> bytes:
        if self._hashed_boot_key is None:
            self._get_hashed_boot_key()
        return self._hashed_boot_key

    @staticmethod
    def _expand_des_key(key: bytes) -> bytes:
        # split to 8 7bit values and fill eigth bit with odd parity
        qs, = struct.unpack('>Q', b'\0' + key)  # convert to 64bit integer (pad high significant bits with \0)
        bit_str = f'{qs:056b}'  # convert to 56 0/1 bit string
        key_bytes = [
            int(bit_str[i:i + 7] + '0', 2)
            for i in range(0, len(bit_str), 7)]  # split every 7 bits and append an odd parity bit
        return bytes(key_bytes)  # convert the resulting 8 one byte values to bytes and append es round_key

    def _decrypt_hash_pre_vista(self, crypted_hash: bytes, bytes_rid: bytes, hashed_boot_key: bytes, md5_salt: bytes):
        des1 = DES.new(self._expand_des_key(bytes_rid + bytes_rid[:3]), mode=DES.MODE_ECB)
        des2 = DES.new(self._expand_des_key(bytes_rid[3:] + bytes_rid + bytes_rid[:2]),
                       mode=DES.MODE_ECB)
        rc4_key = MD5.new(hashed_boot_key[:0x10] + bytes_rid + md5_salt).digest()
        key = ARC4.new(rc4_key).decrypt(crypted_hash)
        hash_decrypted = des1.decrypt(key[:8]) + des2.decrypt(key[8:])
        return hash_decrypted

    def _decrypt_hash(self, crypted_hash: bytes, bytes_rid: bytes, hashed_boot_key: bytes):
        des1 = DES.new(self._expand_des_key(bytes_rid + bytes_rid[:3]), mode=DES.MODE_ECB)
        des2 = DES.new(self._expand_des_key(bytes_rid[3:] + bytes_rid + bytes_rid[:2]),
                       mode=DES.MODE_ECB)
        salt = crypted_hash[0x08:0x18]
        data = crypted_hash[0x18:]
        aes = AES.new(hashed_boot_key[:0x10], mode=AES.MODE_CBC, IV=salt)
        key = aes.decrypt(data)
        hash_decrypted = des1.decrypt(key[:8]) + des2.decrypt(key[8:16])
        return hash_decrypted

    def get_user_infos(self, user_list=None):
        if user_list is None:
            user_list = dict()
        hashed_boot_key = self.hashed_boot_key
        machine_sid = self.machine_sid

        # get user names
        sam_names: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                      db_filter=db_eq(
                                                                          'parent_key', 'HKLM\\SAM\\SAM\\Domains\\'
                                                                                        'Account\\Users\\Names'))
        for sam_name in sam_names:
            if ':' not in sam_name.rtype:
                _logger.warning(f'suspicious rid in SAM/Domains/Account/Users/Names for user {sam_name.name}')
                continue
            _, rid = sam_name.rtype.rsplit(':', 1)
            user_sid = machine_sid + '-' + rid
            if user_sid not in user_list:
                user_list[user_sid] = {}
            user_list[user_sid]['User'] = sam_name.name
            user_list[user_sid]['Created'] = sam_name.timestamp
            if sam_name.deleted:
                user_list[user_sid]['deleted'] = True

        # get sam users
        sam_users: Generator[RegistryEntry] = RegistryEntry.db_select(self._db_reg_cur,
                                                                      db_filter=db_and(
                                                                          db_like('parent_key',
                                                                                  'HKLM\\SAM\\SAM\\Domains\\'
                                                                                  'Account\\Users\\%'),
                                                                          db_in('name', ['F', 'V', 'UserPasswordHint']
                                                                                )
                                                                      ))
        for sam_user in sam_users:
            _, rid = sam_user.parent_key.rsplit('\\', 1)
            int_rid = int(rid, 16)
            bytes_rid = struct.pack('<I', int_rid)
            user_sid = f'{machine_sid}-{int_rid}'
            if user_sid not in user_list:
                user_list[user_sid] = {}
            if sam_user.name == 'UserPasswordHint':
                # need demo data
                pass
            elif sam_user.name == 'F':
                user_f = (UserF(sam_user.get_real_value()))
                if user_f.last_logon.timestamp() > 0:
                    user_list[user_sid]['Last Logon'] = user_f.last_logon
                else:
                    user_list[user_sid]['Last Logon'] = 'never'
                if user_f.last_set_password.timestamp() > 0:
                    user_list[user_sid]['Last Password Change'] = user_f.last_set_password
                else:
                    user_list[user_sid]['Last Password Change'] = 'never'
                if user_f.last_incorrect_password.timestamp() > 0:
                    user_list[user_sid]['Last Failed Login'] = user_f.last_incorrect_password
                else:
                    user_list[user_sid]['Last Failed Login'] = 'never'
                user_list[user_sid]['Failed Login Count'] = user_f.invalid_pw_count
                user_list[user_sid]['Successful Login Count'] = user_f.logon_count
            elif sam_user.name == 'V':
                user_v = UserV(sam_user.get_real_value())
                try:
                    if user_list[user_sid]['User'] != user_v.user:
                        user_list[user_sid]['User V'] = user_v.user
                except KeyError:
                    user_list[user_sid]['User'] = user_v.user
                if user_v.user_comment:
                    user_list[user_sid]['User Comment'] = user_v.user_comment
                if user_v.comment:
                    user_list[user_sid]['Comment'] = user_v.comment
                try:
                    if user_v.profile_path and user_list[user_sid]['Profile Path'] != user_v.profile_path:
                        user_list[user_sid]['Profile Path V'] = user_v.profile_path
                except KeyError:
                    user_list[user_sid]['Profile Path'] = user_v.profile_path

                if user_v.raw_nt_hash[2] == 1:

                    if len(user_v.raw_nt_hash) == 20:
                        nt_hash = user_v.raw_nt_hash[0x04:0x14]
                        nt_hash_decrypted = self._decrypt_hash_pre_vista(nt_hash, bytes_rid,
                                                                         hashed_boot_key, b"NTPASSWORD\0")
                        if nt_hash_decrypted:
                            user_list[user_sid]['NTHash'] = nt_hash_decrypted.hex()
                            hashcat = {'mode': 1000,
                                       'hash': nt_hash_decrypted.hex()}
                            try:
                                user_list[user_sid]['Hashcat'].append(hashcat)
                            except KeyError:
                                user_list[user_sid]['Hashcat'] = [hashcat]
                    if len(user_v.raw_lm_hash) == 20:
                        lm_hash = user_v.raw_lm_hash[0x04:0x14]
                        lm_hash_decrypted = self._decrypt_hash_pre_vista(lm_hash, bytes_rid,
                                                                         hashed_boot_key, b"LMPASSWORD\0")
                        if lm_hash_decrypted:
                            user_list[user_sid]['LMHash'] = lm_hash_decrypted.hex()
                            hashcat = [{'mode': 3000,
                                        'hash': lm_hash_decrypted.hex()[:16]},
                                       {'mode': 3000,
                                        'hash': lm_hash_decrypted.hex()[16:]}]
                            try:
                                user_list[user_sid]['Hashcat'].extend(hashcat)
                            except KeyError:
                                user_list[user_sid]['Hashcat'] = hashcat
                else:
                    # AES
                    if len(user_v.raw_lm_hash) > 24:
                        lm_hash_decrypted = self._decrypt_hash(user_v.raw_lm_hash, bytes_rid, hashed_boot_key)
                        if lm_hash_decrypted:
                            user_list[user_sid]['LMHash'] = lm_hash_decrypted.hex()
                    nt_hash_decrypted = self._decrypt_hash(user_v.raw_nt_hash, bytes_rid, hashed_boot_key)
                    if nt_hash_decrypted:
                        user_list[user_sid]['NTHash'] = nt_hash_decrypted.hex()
        return user_list

    def _get_hashed_boot_key(self):
        aqwerty = b"!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\0"
        anum = b"0123456789012345678901234567890123456789\0"
        domain_f: RegistryEntry = RegistryEntry.db_select_one(self._db_reg_cur,
                                                              db_filter=db_and(
                                                                   db_eq('parent_key',
                                                                         'HKLM\\SAM\\SAM\\Domains\\Account'),
                                                                   db_eq('name', 'F')))
        if not domain_f:
            _logger.warning('unable to read HKLM\\SAM\\SAM\\Domains\\Account\\F')
            return
        value_f = domain_f.get_real_value()
        if len(value_f) < 0x78:
            _logger.warning('value of HKLM\\SAM\\SAM\\Domains\\Account\\F too short')
            return
        revision, = struct.unpack_from('<I', value_f[0x68:])
        if revision == 1:
            if len(value_f) < 0xa0:
                _logger.warning('value of HKLM\\SAM\\SAM\\Domains\\Account\\F (revision 1) too short')
                return
            salt = value_f[0x70:0x80]
            key = value_f[0x80:0x90]
            checksum1 = value_f[0x90:0xa0]
            rc4_key = MD5.new(salt + aqwerty + self._boot_key + anum).digest()
            hashed_bootkey = ARC4.new(rc4_key).decrypt(key + checksum1)
            checksum2 = MD5.new(hashed_bootkey[:16] + anum + hashed_bootkey[:16] + aqwerty).digest()
            if checksum2 == hashed_bootkey[16:]:
                self._hashed_boot_key = hashed_bootkey
            else:
                _logger.warning('unable to verify hashed bootkey (checksum mismatch)')
                return
        elif revision == 2:
            checksum_len, data_len = struct.unpack_from('<II', value_f[0x70:])
            if len(value_f) < 0x88 + data_len:
                _logger.warning('value of HKLM\\SAM\\SAM\\Domains\\Account\\F (revision 2) too short')
                return
            salt = value_f[0x78:0x88]
            data = value_f[0x88:0x88 + data_len]
            aes = AES.new(self._boot_key, mode=AES.MODE_CBC, IV=salt)
            self._hashed_boot_key = aes.decrypt(data)
        else:
            _logger.warning(f'unknown revision {revision} in HKLM\\SAM\\SAM\\Domains\\Account\\F')
            return


class UserF(DefaultClass):
    def __init__(self, reg_content: bytes):
        try:
            self.last_logon = filetime_to_dt(struct.unpack_from('<Q', reg_content[0x08:])[0])
        except (ValueError, OSError):
            self.last_logon = datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            self.last_set_password = filetime_to_dt(struct.unpack_from('<Q', reg_content[0x18:])[0])
        except (ValueError, OSError):
            self.last_set_password = datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            self.account_expires = filetime_to_dt(struct.unpack_from('<Q', reg_content[0x20:])[0])
        except (ValueError, OSError):
            self.account_expires = datetime.fromtimestamp(0, tz=timezone.utc)
        try:
            self.last_incorrect_password = filetime_to_dt(struct.unpack_from('<Q', reg_content[0x28:])[0])
        except (ValueError, OSError):
            self.last_incorrect_password = datetime.fromtimestamp(0, tz=timezone.utc)
        self.rid = struct.unpack_from('<I', reg_content[0x30:])[0]
        self.invalid_pw_count, self.logon_count = struct.unpack_from('<HH', reg_content[0x40:])


class UserV(DefaultClass):
    def __init__(self, reg_content: bytes):
        self._offset_user, self._len_user = struct.unpack_from('<II', reg_content[0x0c:])
        self._offset_fullname, self._len_fullname = struct.unpack_from('<II', reg_content[0x18:])
        self._offset_comment, self._len_comment = struct.unpack_from('<II', reg_content[0x24:])
        self._offset_user_comment, self._len_user_comment = struct.unpack_from('<II', reg_content[0x30:])
        self._offset_home_dir, self._len_home_dir = struct.unpack_from('<II', reg_content[0x48:])
        self._offset_home_dir_connect, self._len_home_dir_connect = struct.unpack_from('<II', reg_content[0x54:])
        self._offset_script_path, self._len_script_path = struct.unpack_from('<II', reg_content[0x60:])
        self._offset_profile_path, self._len_profile_path = struct.unpack_from('<II', reg_content[0x6c:])
        self._offset_workstations, self._len_workstations = struct.unpack_from('<II', reg_content[0x78:])
        self._offset_hours_allowed, self._len_hours_allowed = struct.unpack_from('<II', reg_content[0x84:])
        self._offset_lm_hash, self._len_lm_hash = struct.unpack_from('<II', reg_content[0x9c:])
        self._offset_nt_hash, self._len_nt_hash = struct.unpack_from('<II', reg_content[0xa8:])

        content_offset = 0xcc

        self.user = reg_content[content_offset + self._offset_user:
                                content_offset + self._offset_user + self._len_user].decode('utf16')
        self.fullname = reg_content[content_offset + self._offset_fullname:
                                    content_offset + self._offset_fullname + self._len_fullname].decode('utf16')
        self.comment = reg_content[content_offset + self._offset_comment:
                                   content_offset + self._offset_comment + self._len_comment].decode('utf16')
        self.user_comment = reg_content[content_offset + self._offset_user_comment:
                                        content_offset + self._offset_user_comment +
                                        self._len_user_comment].decode('utf16')
        self.home_dir = reg_content[content_offset + self._offset_home_dir:
                                    content_offset + self._offset_home_dir + self._len_home_dir].decode('utf16')
        self.home_dir_connect = reg_content[content_offset + self._offset_home_dir_connect:
                                            content_offset + self._offset_home_dir_connect +
                                            self._len_home_dir_connect].decode('utf16')
        self.script_path = reg_content[content_offset + self._offset_script_path:
                                       content_offset + self._offset_script_path +
                                       self._len_script_path].decode('utf16')
        self.profile_path = reg_content[content_offset + self._offset_profile_path:
                                        content_offset + self._offset_profile_path +
                                        self._len_profile_path].decode('utf16')
        self.workstations = reg_content[content_offset + self._offset_workstations:
                                        content_offset + self._offset_workstations +
                                        self._len_workstations].decode('utf16')
        self.hours_allowed = reg_content[content_offset + self._offset_hours_allowed:
                                         content_offset + self._offset_hours_allowed + self._len_hours_allowed]

        self.raw_lm_hash = reg_content[content_offset + self._offset_lm_hash:
                                       content_offset + self._offset_lm_hash + self._len_lm_hash]
        self.raw_nt_hash = reg_content[content_offset + self._offset_nt_hash:
                                       content_offset + self._offset_nt_hash + self._len_nt_hash]
