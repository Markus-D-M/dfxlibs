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
import datetime
import logging

from dfxlibs.windows.registry.analysis.system import SYSTEM
from dfxlibs.windows.registry.analysis.software import SOFTWARE
from dfxlibs.windows.registry.analysis.user import USER
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.registry.registryinfo import get_os_infos, get_network_devices, \
    get_user, get_autoruns, Autorun
from dfxlibs.general.helpers.excelwriter import SheetHeader, ExcelTable
from dfxlibs.general.baseclasses.file import File

_logger = logging.getLogger(__name__)


@register_argument('-aar', '--analyze_autoruns', action='store_true',
                   help='list different autorun jobs', group_id='analyze')
def autruns():
    # for windows
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('retrieving autorun information')

    result_table = []
    for partition in image.partitions(part_name=part, only_with_filesystem=True):

        try:
            sqlite_reg_con, sqlite_reg_cur = RegistryEntry.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No registry database. Use --prepare_reg first')

        try:
            sqlite_file_con, sqlite_file_cur = File.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No file database. Use --prepare_files first')

        try:
            env['globals']['system'] = SYSTEM(sqlite_reg_cur)
            env['globals']['software'] = SOFTWARE(sqlite_reg_cur)
            env['globals']['user'] = USER(sqlite_reg_cur)
        except ValueError:
            continue

        autoruns = get_autoruns(sqlite_file_cur, partition)
        for ar in autoruns:
            print(ar)
        result_table.extend(autoruns)
    header = SheetHeader()
    header.title = 'Autoruns'
    header.description = 'List several executables from autorun locations'
    table = ExcelTable()
    table.header = Autorun.table_header
    table.autofilter = True
    table.data = [ar.to_list() for ar in result_table]
    env['results']['Autoruns'] = [header, table]