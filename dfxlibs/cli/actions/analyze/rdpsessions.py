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

from dfxlibs.windows.events.event import Event
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env
from dfxlibs.general.helpers.db_filter import db_eq, db_in, db_and, db_or, db_ge, db_le
from datetime import datetime, timezone, timedelta
from dfxlibs.general.helpers.excelwriter import ExcelTable, SheetHeader, ExcelChart

_logger = logging.getLogger(__name__)


@register_argument('-ardp', '--analyze_rdp_sessions', action='store_true',
                   help='list rdp sessions from system logs', group_id='analyze')
def analyze_rdp_sessions() -> None:
    """
    analysing eventlogs for rdp sessions from channel
    "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" using the event ids
      * 21: Session logon succeeded
      * 24: Session disconnect
      * 25: Session reconnect
    and event id 6005 (System) to retrieve system startups and 6006 (System) for system shutdowns

    :raise IOError: if events are not converted
    :return: None
    """
    # for windows
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('looking for rdp sessions')

    # get all session events
    session_events = []
    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        try:
            sqlite_events_con, sqlite_events_cur = Event.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No event database. Use --prepare_evtx first')

        sql_filter = db_or(
                         db_and(
                             db_in('event_id', [21, 24, 25]),
                             db_eq('channel',
                                   'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational')
                         ),
                         db_and(
                             db_in('event_id', [6005, 6006]),
                             db_eq('channel', 'System')
                         )
                     )
        if env['args'].analyze_start:
            start_date_ts = env['args'].analyze_start.timestamp()
            sql_filter = db_and(sql_filter, db_ge('timestamp_unix', start_date_ts))
        if env['args'].analyze_end:
            end_date_ts = env['args'].analyze_end.timestamp()
            sql_filter = db_and(sql_filter, db_le('timestamp_unix', end_date_ts))

        for event in Event.db_select(sqlite_events_cur, sql_filter):
            session_reasons = {21: 'Session logon',
                               24: 'Session disconnect',
                               25: 'Session reconnect'}

            if event.event_id == 6005:
                session_events.append([event.timestamp, 'SYSTEM START', '-', '-', '-'])
            elif event.event_id == 6006:
                session_events.append([event.timestamp, 'SYSTEM SHUTDOWN', '-', '-', '-'])
            else:
                event_data = event.get_real_data()
                if '.' not in event_data['Address'] and ':' not in event_data['Address']:
                    # no ipv4 or ipv6 -> no rdp session (e.g.LOCAL)
                    continue
                session_events.append([event.timestamp,
                                       session_reasons[event.event_id],
                                       event_data['User'],
                                       event_data['Address'],
                                       event_data['SessionID']])
    session_events.sort(key=lambda x: x[0])

    # build sessions
    expect_action = dict()
    sessions = dict()
    for event in session_events:
        if event[4] not in sessions:
            sessions[event[4]] = []
            try:
                del expect_action[event[4]]
            except KeyError:
                pass
        if event[1] == 'SYSTEM START' or event[1] == 'SYSTEM SHUTDOWN':
            for channel in expect_action:
                if expect_action[channel] == 'logout' and event[1] == 'SYSTEM SHUTDOWN':
                    try:
                        sessions[channel][-1].append(event)
                    except IndexError:
                        sessions[channel].append([event])
            expect_action = dict()
        elif event[1] == 'Session logon' or event[1] == 'Session reconnect':
            expect_action[event[4]] = 'logout'
            sessions[event[4]].append([event])
        elif event[1] == 'Session disconnect':
            expect_action[event[4]] = 'login'
            try:
                sessions[event[4]][-1].append(event)
            except IndexError:
                sessions[event[4]].append([event])

    connections = []
    lowest_dt = None
    highest_dt = None
    for session in sessions:
        for connection in sessions[session]:
            if len(connection) != 2:
                if connection[0][1] == 'Session disconnect':
                    connections.append([datetime.fromtimestamp(0, tz=timezone.utc),
                                        connection[0][0],
                                        connection[0][2], connection[0][3]])
                else:
                    connections.append([connection[0][0],
                                        datetime.fromtimestamp(0, tz=timezone.utc),
                                        connection[0][2], connection[0][3]])
                continue

            if (connection[0][2] != connection[1][2] and connection[1][1] != 'SYSTEM SHUTDOWN') or \
                    (connection[0][3] != connection[1][3] and connection[1][1] != 'SYSTEM SHUTDOWN'):
                _logger.warning('unexpected connection found: ', connection)
            if lowest_dt is None or lowest_dt > connection[0][0]:
                lowest_dt = connection[0][0]
            if highest_dt is None or highest_dt < connection[1][0]:
                highest_dt = connection[1][0]
            connections.append([connection[0][0],
                                connection[1][0],
                                connection[0][2], connection[0][3]])
    connections.sort(key=lambda x: x[0])
    result_table = [[c[0] if c[0].timestamp() > 0 else 'unknown',
                     c[1] if c[1].timestamp() > 0 else 'unknown',
                     c[1] - c[0] if c[0].timestamp() > 0 and c[1].timestamp() > 0 else 'unknown',
                     c[2], c[3]] for c in connections]

    header = SheetHeader()
    header.title = 'RDP Sessions'
    header.description = 'Analyzes Windows eventlogs for rdp sessions from channel ' \
                         '"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" using the event ids ' \
                         '21, 24 and 25 and event ids 6005 and 6006 from channel System to retrieve system startups ' \
                         'and shutdowns'
    table = ExcelTable()
    table.header = ['Session Start (UTC)', 'Session End (UTC)', 'Session Duration', 'User', 'IP Address']
    table.autofilter = True
    table.data = result_table
    env['results']['RDP Sessions'] = [header, table]

    dows = [set() for _ in range(7)]
    hours = [set() for _ in range(24)]
    for connection in connections:
        start = connection[0].replace(minute=0, second=0, microsecond=0)
        end = (connection[1] + timedelta(hours=1)).replace(minute=0, second=0, microsecond=0)
        if connection[0].timestamp() == 0:
            start = end
        if connection[1].timestamp() == 0:
            end = start
        akt = start
        while akt != end:
            str_day = f'{akt.year}-{akt.month}-{akt.day}'
            hours[akt.hour].add(str_day)
            dows[akt.weekday()].add(str_day)
            akt = akt + timedelta(hours=1)
    hours = [len(h) for h in hours]
    dows = [len(d) for d in dows]

    charthours = ExcelChart()
    charthours.type = 'column'
    charthours.values = hours
    charthours.categories = [f'{i:02d}-{i+1:02d}' for i in range(24)]
    charthours.title = 'Sessions per Hour (UTC)'

    chartdows = ExcelChart()
    chartdows.type = 'column'
    chartdows.values = dows
    chartdows.categories = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
    chartdows.title = 'Sessions per Day of Week'

    header2 = SheetHeader()
    header2.title = 'RDP Sessions Distribution Charts'
    header2.description = 'Shows the rdp session distribution per hour and per day of week in two charts. ' \
                          'The chart shows that at hour X (UTC) or day X (UTC) there were at least one rdp session ' \
                          'at Y different days.'
    env['results']['RDP Sessions Distribution'] = [header2, charthours, chartdows]

    #for connection in result_table:
    #    print (connection)