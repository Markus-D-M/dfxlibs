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

from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.timeline import Timeline
from dfxlibs.windows.usnjournal.usnrecordv2 import USNRecordV2, usn_carver
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env


_logger = logging.getLogger(__name__)


@register_argument('-cusn', '--carve_usn', action='store_true', help='carve for ntfs usn journal entries and stores '
                                                                     'them in the same database as for the '
                                                                     '--prepare_usn argument', group_id='carve')
def carve_usnjournal() -> None:
    """
    carve partitions for usn journal entries in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only this partition is scanned.

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    :raise ValueError: if USN journal is broken
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start carving usn journal')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        _logger.info(f'carving usn journal in partition {partition.part_name}')

        try:
            _, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            # Don't find parents
            sqlite_files_cur = None

        sqlite_usn_con, sqlite_usn_cur = USNRecordV2.db_open(meta_folder, partition.part_name)
        sqlite_timeline_con, sqlite_timeline_cur = Timeline.db_open(meta_folder, partition.part_name)

        parent_folders = {}
        count = 0
        usnrecord: USNRecordV2
        renames_old = dict()
        states_old = dict()
        for usnrecord in partition.carve(usn_carver):
            if sqlite_files_cur is not None:
                usnrecord.retrieve_parent_folder(parent_folders, sqlite_files_cur)
            if usnrecord.db_insert(sqlite_usn_cur):
                count += 1
            # State tracking for timeline
            file_meta = f'{usnrecord.file_addr}-{usnrecord.file_seq}'
            if file_meta not in states_old:
                new_states = usnrecord.hr_reason_to_int(usnrecord.reason)
            else:
                new_states = ~states_old[file_meta] & usnrecord.hr_reason_to_int(usnrecord.reason)
            states_old[file_meta] = usnrecord.hr_reason_to_int(usnrecord.reason)
            if new_states & usnrecord.USN_REASON_FILE_CREATE:
                tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                              event_type='FILE_CREATE',
                              message=f'{usnrecord.full_name} created',
                              param1=usnrecord.name, param2=usnrecord.parent_folder)
                tl.db_insert(sqlite_timeline_cur)
            if new_states & usnrecord.USN_REASON_FILE_DELETE:
                tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                              event_type='FILE_DELETE',
                              message=f'{usnrecord.full_name} deleted',
                              param1=usnrecord.name, param2=usnrecord.parent_folder)
                tl.db_insert(sqlite_timeline_cur)
            if new_states & usnrecord.USN_REASON_RENAME_OLD_NAME:
                renames_old[file_meta] = (usnrecord.name, usnrecord.parent_folder, usnrecord.full_name)
            if new_states & usnrecord.USN_REASON_RENAME_NEW_NAME and file_meta in renames_old:
                tl = Timeline(timestamp=usnrecord.timestamp, event_source='usnjournal',
                              event_type='FILE_RENAME',
                              message=f'{renames_old[file_meta][2]} renamed to {usnrecord.full_name}',
                              param1=usnrecord.name, param2=usnrecord.parent_folder,
                              param3=renames_old[file_meta][0], param4=renames_old[file_meta][1])
                tl.db_insert(sqlite_timeline_cur)
                del renames_old[file_meta]
            if new_states & usnrecord.USN_REASON_CLOSE:
                del states_old[file_meta]

        sqlite_usn_con.commit()
        sqlite_timeline_con.commit()
        _logger.info(f'{count} usn records added for partition {partition.part_name}')

    _logger.info('carving usn records finished')
