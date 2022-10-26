# coding: utf-8
"""
    dfxlibs cli --list_partitions

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

import dfxlibs
from dfxlibs.general.helpers import bytes_to_hr
from dfxlibs.cli.arguments import register_argument
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dfxlibs.cli.environment import Environment


_logger = logging.getLogger(__name__)


@register_argument('-lp', '--list_partitions', action='store_true', help='print partition list', group_id='special')
def list_partitions(env: 'Environment') -> None:
    """
    List all partitions in a given image

    :param env: cli environment
    :type env: Environment
    :return: None
    :raise AttributeError: if image is None
    """
    image = env['image']
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')
    if len(image.filenames) > 1:
        print(f'Image files: {image.filenames[0]}, {image.filenames[1]}, ...')
    else:
        print(f'Image file: {image.filenames[0]}')
    print(f'Image size: {dfxlibs.general.helpers.bytes_to_hr(image.size)}, {image.size} bytes')
    print(f'Sector size: {image.sector_size} bytes')
    print(f'Partition table type: {image.vstype}')
    print('')
    print(f'{"Partition":10} {"Start":>10} {"End":>10} {"Sectors":>10} {"Size":>10}  {"Id":>4} {"Crypt":>5} '
          f'Description')
    for partition in image.partitions():
        print(f'{partition.part_name:<10} {partition.sector_offset:10} '
              f'{partition.sector_offset+partition.sector_count:10} {partition.sector_count:10} '
              f'{bytes_to_hr(partition.bytes_size):>10}  0x{partition.type_id:02x} '
              f'{("Y" if partition.is_crypted else "N"):>5} {partition.descr}')
