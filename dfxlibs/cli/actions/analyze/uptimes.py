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
from dfxlibs.general.helpers.db_filter import db_and, db_ge, db_le
from datetime import datetime, timezone
from dfxlibs.general.helpers.excelwriter import ExcelTable, SheetHeader

_logger = logging.getLogger(__name__)


@register_argument('-aut', '--analyze_uptimes', action='store_true',
                   help='list timeranges, when the system was up and running. Up and running is defined by at least '
                        'one eventlog entry within 60 minutes',
                   group_id='analyze')
def analyze_uptimes() -> None:
    """
    analysing eventlogs for system uptimes:
    At least 1 eventlog entry per 60 minutes defines the system as active.

    :raise IOError: if events are not converted
    :return: None
    """
    # for windows
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('looking for uptimes')
    ranges = []

    # specified partitions only (if specified)
    for partition in image.partitions(part_name=part, only_with_filesystem=True):
        try:
            sqlite_events_con, sqlite_events_cur = Event.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No event database. Use --prepare_evtx first')

        sql_filter = ('1=?', (1,))

        if env['args'].analyze_start:
            start_date_ts = env['args'].analyze_start.timestamp()
            sql_filter = db_and(sql_filter, db_ge('timestamp_unix', start_date_ts))
        if env['args'].analyze_end:
            end_date_ts = env['args'].analyze_end.timestamp()
            sql_filter = db_and(sql_filter, db_le('timestamp_unix', end_date_ts))

        current_range_start = 0
        current_range_end = 0
        max_seconds_between_events = 3600
        for event in Event.db_select(sqlite_events_cur, sql_filter, order_by='timestamp_unix'):
            if current_range_start == 0:
                current_range_start = event.timestamp.timestamp()
                current_range_end = event.timestamp.timestamp()
            elif event.timestamp.timestamp() - current_range_end < max_seconds_between_events:
                current_range_end = event.timestamp.timestamp()
            else:
                dt_start = datetime.fromtimestamp(current_range_start, tz=timezone.utc).replace(second=0, microsecond=0)
                dt_end = datetime.fromtimestamp(current_range_end, tz=timezone.utc).replace(second=0, microsecond=0)
                ranges.append([dt_start, dt_end, dt_end - dt_start])
                current_range_start = event.timestamp.timestamp()
                current_range_end = event.timestamp.timestamp()
        if current_range_start > 0:
            dt_start = datetime.fromtimestamp(current_range_start, tz=timezone.utc).replace(second=0, microsecond=0)
            dt_end = datetime.fromtimestamp(current_range_end, tz=timezone.utc).replace(second=0, microsecond=0)
            ranges.append([dt_start, dt_end, dt_end - dt_start])

    header = SheetHeader()
    header.title = 'Uptimes'
    header.description = 'List uptimes of the given system. If there is at least one eventlog entry within 60 minutes' \
                         ', it counts as continuous uptime.'
    table = ExcelTable()
    table.header = ['Uptime Start (UTC)', 'Uptime End (UTC)', 'Uptime Duration']
    table.autofilter = True
    table.data = ranges
    env['results']['Uptimes'] = [header, table]
