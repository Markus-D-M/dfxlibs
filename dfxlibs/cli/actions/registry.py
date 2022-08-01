# coding: utf-8
"""
    dfxlibs cli --convert-reg

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
import sqlite3
import os
from Registry import Registry, RegistryParse
from datetime import datetime, timezone
from json import dumps

import dfxlibs

_logger = logging.getLogger(__name__)


def recursive_registry(key, db_cur: sqlite3.Cursor = None, mount_point: str = None):
    # replace 'ROOT' with mountpoint
    path = mount_point + key.path()[4:]
    try:
        value = key.value('(default)')
        value_type = value.value_type_str()
        value_name = value.name()
        value_timestamp = key.timestamp().replace(tzinfo=timezone.utc)
        try:
            value_content = value.value()
        except RegistryParse.UnknownTypeException:
            value_content = value.raw_data()
    except Registry.RegistryValueNotFoundException:
        value_type = 'RegSZ'
        value_name = '(default)'
        value_content = '(value not set)'
        value_timestamp = key.timestamp().replace(tzinfo=timezone.utc)
    regentry = dfxlibs.windows.registryentry.RegistryEntry(value_timestamp, path , value_name,
                                                           value_type, value_content)
    try:
        db_cur.execute(*regentry.db_create_insert())
    except sqlite3.IntegrityError:
        pass
    except sqlite3.OperationalError:
        # Create table if not exists
        for create_command in regentry.db_create_table():
            db_cur.execute(create_command)
        db_cur.execute(*regentry.db_create_insert())

    # values
    for value in key.values():
        if value.name() == '(default)':
            continue
        value_type = value.value_type_str()
        value_name = value.name()
        try:
            value_content = value.value()
        except RegistryParse.UnknownTypeException:
            value_content = value.raw_data()
        value_timestamp = datetime.fromtimestamp(0, tz=timezone.utc)
        if type(value_content) is bytes:
            value_content = value_content.hex()
        elif type(value_content) is datetime:
            value_content = value_content.timestamp()
        regentry = dfxlibs.windows.registryentry.RegistryEntry(value_timestamp, path, value_name,
                                                               value_type, value_content)
        try:
            db_cur.execute(*regentry.db_create_insert())
        except sqlite3.IntegrityError:
            pass

    for subkey in key.subkeys():
        recursive_registry(subkey, db_cur, mount_point)


def convert_registry(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> None:
    """
    scans the windows registry in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :param image: image file
    :type image: dfxlibs.general.image.Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    partitions = image.partitions
    for partition in partitions:
        if part is not None and f'{partition.table_num}_{partition.slot_num}' != part:
            continue
        file_db = os.path.join(meta_folder, f'files_{partition.table_num}_{partition.slot_num}.db')
        if not os.path.isfile(file_db):
            raise IOError('ERROR: No file database. Use --scan_files first')

        sqlite_registry_con = sqlite3.connect(
            os.path.join(meta_folder, f'registry_{partition.table_num}_{partition.slot_num}.db'))
        sqlite_registry_con.row_factory = dfxlibs.windows.registryentry.RegistryEntry.db_factory
        sqlite_registry_cur = sqlite_registry_con.cursor()
        _logger.info("storing registry in " +
                     os.path.join(meta_folder, f'registry_{partition.table_num}_{partition.slot_num}.db'))

        sqlite_files_con = sqlite3.connect(file_db)
        sqlite_files_con.row_factory = dfxlibs.general.baseclasses.file.File.db_factory
        sqlite_files_cur = sqlite_files_con.cursor()

        # System hives
        hives = [{'filename': 'SYSTEM', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKLM\\SYSTEM'},
                 {'filename': 'SOFTWARE', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKLM\\SOFTWARE'},
                 {'filename': 'SAM', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKLM\\SAM'},
                 {'filename': 'SECURITY', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKLM\\SECURITY'},
                 {'filename': 'DRIVERS', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKLM\\DRIVERS'},
                 {'filename': 'DEFAULT', 'filepath': r'/Windows/System32/config', 'mountpoint': 'HKU\\.DEFAULT'},
                 {'filename': 'NTUSER.DAT', 'filepath': r'/Windows/ServiceProfiles/LocalService',
                  'mountpoint': 'HKU\\S-1-5-19'},
                 {'filename': 'NTUSER.DAT', 'filepath': r'/Windows/ServiceProfiles/NetworkService',
                  'mountpoint': 'HKU\\S-1-5-20'}
                 ]
        for hive in hives:
            sqlite_files_cur.execute(r'SELECT * FROM File WHERE name=? and parent_folder=? and allocated=?',
                                     (hive['filename'], hive['filepath'], 1))
            hive_file = sqlite_files_cur.fetchone()
            if not hive_file:
                # hive not found (perhaps no windows system partition)
                continue
            hive_file.open(partition)
            hive_reg = Registry.Registry(hive_file)
            recursive_registry(hive_reg.root(), sqlite_registry_cur, hive['mountpoint'])
            sqlite_registry_con.commit()

        # User hives
        try:
            sqlite_registry_cur.execute(r'SELECT * FROM RegistryEntry WHERE '
                                        r'key like '
                                        r'"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\S-1-5-21%" '
                                        r'and value_name = "ProfileImagePath"')
            user_profiles = sqlite_registry_cur.fetchall()
        except sqlite3.OperationalError:
            # no hives in this partition
            user_profiles = []

        for user_profile in user_profiles:
            _, sid = user_profile.key.rsplit('\\', 1)
            profile_folder = user_profile.get_real_value()[2:].replace('\\', '/')
            hives = [
                {'filename': 'NTUSER.DAT', 'filepath': profile_folder,
                 'mountpoint': f'HKU\\{sid}'},
                {'filename': 'UsrClass.dat', 'filepath': f'{profile_folder}/AppData/Local/Microsoft/Windows',
                 'mountpoint': f'HKU\\S-1-'}] # Classes hive does not start with 'ROOT'
            for hive in hives:
                sqlite_files_cur.execute(r'SELECT * FROM File WHERE name=? and parent_folder=? and allocated=?',
                                         (hive['filename'], hive['filepath'], 1))
                hive_file = sqlite_files_cur.fetchone()
                if not hive_file:
                    _logger.warning(f'profile hive in {profile_folder} not found')
                    continue
                hive_file.open(partition)
                hive_reg = Registry.Registry(hive_file)
                recursive_registry(hive_reg.root(), sqlite_registry_cur, hive['mountpoint'])
                sqlite_registry_con.commit()

