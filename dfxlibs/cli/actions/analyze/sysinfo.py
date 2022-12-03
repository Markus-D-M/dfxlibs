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

from dfxlibs.windows.registry.analysis.sam import SAM
from dfxlibs.windows.registry.analysis.system import SYSTEM
from dfxlibs.windows.registry.analysis.security import SECURITY
from dfxlibs.windows.registry.analysis.software import SOFTWARE
from dfxlibs.cli.arguments import register_argument
from dfxlibs.cli.environment import env
from dfxlibs.windows.registry.registryentry import RegistryEntry
from dfxlibs.windows.registry.registryinfo import get_os_infos, get_network_devices, \
    get_user
from dfxlibs.general.helpers.excelwriter import SheetHeader, ExcelList

_logger = logging.getLogger(__name__)


@register_argument('-asi', '--analyze_sys_infos', action='store_true',
                   help='list multiple system information', group_id='analyze')
def sysinfo():
    # for windows
    image = env['image']
    part = env['args'].part
    meta_folder = env['meta_folder']

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    _logger.info('retrieving system information')

    result = ExcelList()
    dcc_result = []
    os_info_result = []
    net_info_result = []
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
        except ValueError:
            continue

        os_infos = get_os_infos(sqlite_reg_cur)
        for name in os_infos:
            os_info_result.append((name, os_infos[name]))

        net_infos = get_network_devices(sqlite_reg_cur)
        for adapter_guid, adapter_info in net_infos.items():
            if 'IPAddress' not in adapter_info or adapter_info['IPAddress'] in ['', '0.0.0.0']:
                # adapters with active ip only
                continue
            net_info_result.append(('Adapter Name:', adapter_info['Name']))
            net_info_result.append(('GUID:', adapter_guid))
            net_info_result.append(('DHCP:', 'yes' if adapter_info['DHCP'] else 'no'))
            net_info_result.append(('IP Address:', adapter_info['IPAddress']))
            net_info_result.append(('Subnet Mask:', adapter_info['SubnetMask']))
            if 'DefaultGateway' in adapter_info:
                net_info_result.append(('Default Gateway:', adapter_info['DefaultGateway']))
            net_info_result.append(('', ''))

            dcc = env['globals']['security'].domain_cache
            for nl_record in dcc.nl_records:
                dcc_result.append(('User:', f'{nl_record.domain_name}\\{nl_record.user}'))
                dcc_result.append(('User Id:', nl_record.rid))
                dcc_result.append(('User Principal Name:', nl_record.upn))
                dcc_result.append(('Full Name:', nl_record.full_name))
                if env['globals']['security'].is_pre_vista:
                    dcc_result.append(('MS Cache V1:', nl_record.ms_cache.hex()))
                    dcc_result.append(('Hashcat:', nl_record.get_hashcat_row(dcc.iteration_count)))
                else:
                    dcc_result.append(('MS Cache V2:', nl_record.ms_cache.hex()))
                    dcc_result.append(('Hashcat:', nl_record.get_hashcat_row(dcc.iteration_count)))
                dcc_result.append(('', ''))
        print (get_user(sqlite_reg_cur))

    result.add_section('Operating System Information', os_info_result)
    result.add_section('Active Network Devices', net_info_result)
    result.add_section('Cached Domain Credentials', dcc_result)
    header = SheetHeader()
    header.title = 'System Information'
    header.description = 'List multiple different system and user information'
    env['results']['SysInfo'] = [header, result]
