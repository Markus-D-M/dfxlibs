# coding: utf-8
"""
    dfxlibs cli --convert-evtx


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
import datetime

import dfxlibs
import sqlite3
import os.path
import logging

from typing import List


_logger = logging.getLogger(__name__)


def convert_evtx(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> None:
    """
    read all windows evtx logs in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :param image: image file
    :type image: dfxlibs.general.image.Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    :raise IOError: if image is not scanned for files
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
        sqlite_files_con = sqlite3.connect(file_db)
        sqlite_files_con.row_factory = dfxlibs.general.baseclasses.file.File.db_factory
        sqlite_files_cur = sqlite_files_con.cursor()
        sqlite_files_cur.execute('SELECT * FROM File WHERE name like "%.evtx"')

        sqlite_events_con = sqlite3.connect(
            os.path.join(meta_folder, f'events_{partition.table_num}_{partition.slot_num}.db'))
        sqlite_events_con.row_factory = dfxlibs.windows.events.event.Event.db_factory
        sqlite_events_cur = sqlite_events_con.cursor()
        first_event = True
        record_count = 0
        file_count = 0
        for file in sqlite_files_cur.fetchall():
            file.open(partition)
            try:
                evtx_file = dfxlibs.windows.evtxfile.EvtxFile(file)
            except IOError as e:
                _logger.warning(f'{file.name}: {e}')
                continue
            _logger.info(f'reading file {file.name}')
            file_count += 1
            file_record_count = 0
            for event in evtx_file.records:
                if first_event:
                    for create_command in event.db_create_table():
                        sqlite_events_cur.execute(create_command)
                    first_event = False
                    _logger.info("storing eventlogs in " +
                                 os.path.join(meta_folder, f'events_{partition.table_num}_{partition.slot_num}.db'))
                try:
                    sqlite_events_cur.execute(*event.db_create_insert())
                    record_count += 1
                    file_record_count += 1
                except sqlite3.IntegrityError:
                    pass
            _logger.info(f'{file_record_count} event records added')
        sqlite_events_con.commit()
        _logger.info(f'{record_count} event records from {file_count} files added for '
                     f'partition {partition.table_num}_{partition.slot_num}')


def carve_evtx(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> None:
    """
    carve all windows evtx logs in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the data of this partition is scanned

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

        sqlite_events_con = sqlite3.connect(
            os.path.join(meta_folder, f'events_{partition.table_num}_{partition.slot_num}.db'))
        sqlite_events_con.row_factory = dfxlibs.windows.events.event.Event.db_factory
        sqlite_events_cur = sqlite_events_con.cursor()
        first_event = True
        record_count = 0
        carver = dfxlibs.windows.evtxcarver.EvtxCarver(partition)
        for event in carver.records:
            if first_event:
                for create_command in event.db_create_table():
                    sqlite_events_cur.execute(create_command)
                first_event = False
                _logger.info("storing carved event records in " +
                             os.path.join(meta_folder, f'events_{partition.table_num}_{partition.slot_num}.db'))
            try:
                sqlite_events_cur.execute(*event.db_create_insert())
                record_count += 1
            except sqlite3.IntegrityError:
                pass
        sqlite_events_con.commit()
        _logger.info(f'{record_count} event records carved for '
                     f'partition {partition.table_num}_{partition.slot_num}')


def get_user_sessions(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> List:
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

    partitions = image.partitions
    result = []
    for partition in partitions:
        if part is not None and f'{partition.table_num}_{partition.slot_num}' != part:
            continue
        events_db = os.path.join(meta_folder, f'events_{partition.table_num}_{partition.slot_num}.db')
        if not os.path.isfile(events_db):
            raise IOError('ERROR: No events database. Use --convert_evtx first')
        sqlite_events_con = sqlite3.connect(events_db)
        sqlite_events_con.row_factory = dfxlibs.windows.events.event.Event.db_factory
        sqlite_events_cur = sqlite_events_con.cursor()

        sqlite_events_cur.execute('SELECT * FROM Event WHERE (event_id in (21, 24, 25) '
                                  'AND channel="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational")'
                                  'OR (channel="System" and event_id = 6005)')
        events = sqlite_events_cur.fetchall()
        for event in events:
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
    return result
