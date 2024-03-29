# coding: utf-8
"""
    dfxlibs cli --prepare-evtx


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

from typing import List

from dfxlibs.general.image import Image
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.timeline import Timeline
from dfxlibs.windows.events.evtxfile import EvtxFile
from dfxlibs.windows.events.event import Event
from dfxlibs.general.helpers.db_filter import db_eq, db_or, db_and, db_in, db_gt
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env



_logger = logging.getLogger(__name__)


@register_argument('-pevtx', '--prepare_evtx', action='store_true', help='read all windows evtx logs in a given Image '
                                                                         'and stores them in a sqlite database in the '
                                                                         'meta_folder.  You can specify a partition '
                                                                         'with --part. ', group_id='prepare')
def prepare_evtx() -> None:
    """
    read all windows evtx logs in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
    """
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('start preparing event (evtx) logs')

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        _logger.info(f'preparing events in partition {partition.part_name}')

        try:
            sqlite_files_con, sqlite_files_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        sqlite_events_con, sqlite_events_cur = Event.db_open(meta_folder, partition.part_name)
        sqlite_timeline_con, sqlite_timeline_cur = Timeline.db_open(meta_folder, partition.part_name)

        record_count = 0
        file_count = 0
        for file in File.db_select(sqlite_files_cur, db_and(db_eq('extension', 'evtx'), db_gt('size', 0)),
                                   force_index_column='extension'):
            file.open(partition)
            try:
                evtx_file = EvtxFile(file)
            except IOError as e:
                _logger.warning(f'{file.source}:{file.name}: {e}')
                continue
            _logger.info(f'reading file {file.source}:{file.name}')
            file_count += 1
            file_record_count = 0
            file_skip_count = 0
            try:
                for event in evtx_file.records:
                    if event.db_insert(sqlite_events_cur):
                        record_count += 1
                        file_record_count += 1
                    else:
                        file_skip_count += 1
                    tl = Timeline(timestamp=event.timestamp, event_source='eventlog',
                                  event_type='EVENT',
                                  param1=event.channel, param2=str(event.event_id), param3=event.data)
                    tl.db_insert(sqlite_timeline_cur)
            except OSError:
                _logger.error(f'error while reading file {file.source}:{file.name} - skipping')
            _logger.info(f'{file_record_count} event records added ({file_skip_count} skipped)')
        sqlite_events_con.commit()
        sqlite_timeline_con.commit()
        _logger.info(f'{record_count} event records from {file_count} files added for '
                     f'partition {partition.part_name}')


def get_user_sessions(image: Image, meta_folder: str, part: str = None) -> List:
    """
    analysing eventlogs for user sessions from channel
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" using the event ids
      * 21: Session logon succeeded
      * 24: Session disconnect
      * 25: Session reconnect
    and event id 6005 (System) to retrieve system startups

    :param image: image file
    :type image: dfxlibs.general.image.Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: List of session events ordered by timestamp [timestamp, reason, user, remote_ip, sessionid]
    :rtype: List
    :raise AttributeError: if image is None
    :raise IOError: if events are not converted

    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('getting user sessions from eventlogs')

    result = []
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part):
        try:
            sqlite_events_con, sqlite_events_cur = Event.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No events database. Use --prepare_evtx first')

        _logger.info(f'getting user sessions from partition {partition.part_name}')

        for event in Event.db_select(sqlite_events_cur,
                                     db_or(
                                         db_and(
                                             db_in('event_id', [21, 24, 25]),
                                             db_eq('channel',
                                                   'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
                                         ),
                                         db_and(
                                             db_eq('event_id', 6005),
                                             db_eq('channel', 'system')
                                         )
                                     )):
            session_reasons = {21: 'Session logon',
                               24: 'Session disconnect',
                               25: 'Session reconnect'}
            if event.event_id == 6005:
                result.append([event.timestamp.isoformat(), 'SYSTEM RESTART', '-', '-', '-'])
            else:
                event_data = event.get_real_data()
                result.append([event.timestamp.isoformat(),
                               session_reasons[event.event_id],
                               event_data['User'],
                               event_data['Address'],
                               event_data['SessionID']])
    result.sort(key=lambda x: x[0])
    result.insert(0, ['Timestamp', 'Event', 'User', 'Remote IP', 'Session ID'])
    _logger.info('getting user sessions finished')

    return result
