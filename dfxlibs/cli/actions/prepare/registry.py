# coding: utf-8
"""
    dfxlibs cli --prepare-reg

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

from dfxlibs.cli.environment import env
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.helpers.db_filter import db_and, db_like, db_eq
from dfxlibs.cli.arguments import register_argument
from dfxlibs.windows.registry.registryparser import parse_registry

_logger = logging.getLogger(__name__)


@register_argument('-preg', '--prepare_reg', action='store_true', help='read the windows registry and stores them in a '
                                                                       'sqlite database in the meta_folder. You can '
                                                                       'specify a partition with --part.',
                   group_id='prepare')
def prepare_registry() -> None:
    """
    scans the windows registry in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :return: None
    :raise AttributeError: if image is None
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing registry')
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):

        sqlite_registry_con, sqlite_registry_ro, sqlite_registry_rw = RegistryEntry.db_open(meta_folder,
                                                                                            partition.part_name,
                                                                                            generate_cursors_num=2)

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

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
                  'mountpoint': 'HKU\\S-1-5-20'},
                 {'filename': 'Amcache.hve', 'filepath': r'%/appcompat/Programs',
                  'mountpoint': 'AMCACHE'}
                 ]
        for hive in hives:
            hive_file = File.db_select_one(sqlite_files_cur, db_and(
                                                                    db_like('name', hive['filename']),
                                                                    db_like('parent_folder', hive['filepath']),
                                                                    db_eq('allocated', 1),
                                                                    db_eq('source', 'filesystem')
                                                                   )
                                           )
            if not hive_file:
                # hive not found (perhaps no windows system partition)
                continue
            hive_file.open(partition)
            hive_buf = hive_file.read()

            for reg_entry in parse_registry(hive_buf, hive['mountpoint']):
                reg_entry.db_insert(sqlite_registry_rw)

            sqlite_registry_con.commit()

        for user_profile in RegistryEntry.db_select(sqlite_registry_ro, db_and(
                db_like('parent_key', 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\S-1-5-21%'),
                db_eq('name', 'ProfileImagePath')
                )):
            _, sid = user_profile.parent_key.rsplit('\\', 1)
            _, folder = user_profile.get_real_value().split('\\', 1)
            profile_folder = '/' + folder.replace('\\', '/')
            hives = [
                {'filename': 'NTUSER.DAT', 'filepath': profile_folder,
                 'mountpoint': f'HKU\\{sid}'},
                {'filename': 'UsrClass.dat', 'filepath': f'{profile_folder}/AppData/Local/Microsoft/Windows',
                 'mountpoint': f'HKU\\{sid}_Classes'}]
            for hive in hives:
                hive_file = File.db_select_one(sqlite_files_cur, db_and(
                        db_eq('name', hive['filename']),
                        db_eq('parent_folder', hive['filepath']),
                        db_eq('allocated', 1),
                        db_eq('source', 'filesystem')
                    ))
                if not hive_file:
                    _logger.warning(f'profile hive {hive["filename"]} in profile {profile_folder} not found')
                    continue

                hive_file.open(partition)
                hive_buf = hive_file.read()

                for reg_entry in parse_registry(hive_buf, hive['mountpoint']):
                    reg_entry.db_insert(sqlite_registry_rw)

                sqlite_registry_con.commit()

    _logger.info('preparing registry finished')
