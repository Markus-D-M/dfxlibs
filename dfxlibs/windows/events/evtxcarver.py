# coding: utf-8
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
from struct import unpack
from typing import Iterator
from Evtx.Evtx import ChunkHeader
import dfxlibs
from lxml import etree
from Evtx.BinaryParser import OverrunBufferException, ParseException
from lxml.etree import XMLSyntaxError
from .xml_to_dict import xml_to_dict
from .event import Event

_logger = logging.getLogger(__name__)


class EvtxCarver:
    def __init__(self, partition: dfxlibs.general.baseclasses.partition.Partition):
        self._partition = partition

    @property
    def records(self) -> Iterator[Event]:
        data_count = 0
        partition_bytes_offset = 0
        chunk_size_mb = 50
        offset_step = 512
        chunk_size = 1024 * 1024 * chunk_size_mb
        current_data = b''
        current_data_offset = 0
        last_round = False
        while not last_round:
            data_chunk = self._partition.read_buffer(chunk_size, partition_bytes_offset)
            partition_bytes_offset += len(data_chunk)
            data_count += 1
            if not data_chunk:
                data_chunk = b'\0' * chunk_size
                last_round = True
            current_data = current_data[current_data_offset:] + data_chunk
            current_data_offset = 0
            current_data_len = len(current_data)
            print(f'\r{data_count * chunk_size_mb}MiB...', end='')
            while current_data_len - current_data_offset > 0xffff:
                if current_data[current_data_offset:current_data_offset + 8] != b'ElfChnk\0' or \
                        current_data[current_data_offset + 40] != 128 or \
                        current_data[current_data_offset + 512:current_data_offset + 516] != b'**\0\0':
                    current_data_offset += offset_step
                    continue

                chunk = ChunkHeader(current_data, current_data_offset)
                for record in chunk.records():
                    try:
                        evt_tree: etree = record.lxml()
                    except (OverrunBufferException, UnicodeDecodeError, KeyError, ParseException,
                            XMLSyntaxError, AttributeError, IndexError, RecursionError):
                        # Parse errors for partial destroyed chunks -> ignore records
                        continue
                    try:
                        event = xml_to_dict(evt_tree)
                        event['carved'] = True
                    except (ValueError, IndexError):
                        continue
                    yield Event(**event)
                current_data_offset += offset_step


