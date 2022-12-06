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

from dfxlibs.windows.registry.analysis.sam import SAM
from dfxlibs.windows.registry.analysis.system import SYSTEM
from dfxlibs.windows.registry.analysis.security import SECURITY
from dfxlibs.windows.registry.analysis.software import SOFTWARE
from dfxlibs.windows.registry.analysis.user import USER
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.registry.registryinfo import get_os_infos, get_network_devices, \
    get_user
from dfxlibs.general.helpers.excelwriter import SheetHeader, ExcelList

_logger = logging.getLogger(__name__)


@register_argument('-aui', '--analyze_user_infos', action='store_true',
                   help='list multiple user information', group_id='analyze')
def sysinfo():
    # for windows
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('retrieving system information')

    result = ExcelList()
    for partition in image.partitions(part_name=part, only_with_filesystem=True):

        try:
            sqlite_reg_con, sqlite_reg_cur = RegistryEntry.db_open(meta_folder, partition.part_name, False)
        except IOError:
            raise IOError('ERROR: No registry database. Use --prepare_reg first')

        try:
            env['globals']['system'] = SYSTEM(sqlite_reg_cur)
            env['globals']['sam'] = SAM(sqlite_reg_cur, env['globals']['system'].boot_key)
            env['globals']['security'] = SECURITY(sqlite_reg_cur, env['globals']['system'].boot_key)
            env['globals']['software'] = SOFTWARE(sqlite_reg_cur)
            env['globals']['user'] = USER(sqlite_reg_cur)
        except ValueError:
            continue

        user = get_user(sqlite_reg_cur)
        for sid, user_info in user.items():
            user_name = ''
            info_list = [('SID', sid)]
            for k, v in user_info.items():
                if type(v) is datetime.datetime:
                    v = v.isoformat()
                if k == 'User':
                    info_list.append((k, v))
                    user_name = v
                elif k == 'Hashcat' and type(v) is list:
                    info_list.append((k, '\n'.join([f'Mode: {i["mode"]}; Hash: {i["hash"]}' for i in v])))
                elif type(v) is list:
                    info_list.append((k, '\n'.join(v)))
                else:
                    info_list.append((k, v))
            if user_name:
                result.add_section(f'User {user_name}', info_list)
            else:
                result.add_section(f'User {sid}', info_list)

    header = SheetHeader()
    header.title = 'User Information'
    header.description = 'List multiple different user information'
    env['results']['UserInfo'] = [header, result]
