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
from Evtx.BinaryParser import OverrunBufferException
from lxml.etree import XMLSyntaxError
from .xml_to_dict import xml_to_dict
from .event import Event

_logger = logging.getLogger(__name__)


class EvtxFile:
    def __init__(self, file: dfxlibs.general.baseclasses.file.File):
        self._file = file
        if self._file.size < 4096:
            _logger.error('file to small')
            raise IOError()
        self._file.seek(0)
        header = self._file.read(4096)
        if header[:8] != b'ElfFile\0':
            raise IOError('Not a windows event file (bad magic)')
        first_chunk_number, last_chunk_number, next_record_identifier, header_size, minor_version, major_version, \
            header_block_size, number_of_chunks, file_flags, checksum = unpack('<3QI4H76x2I', header[8:128])
        if header_size != 128 or major_version != 3 or header_block_size != 4096:
            raise IOError('Not a windows event file (bad header)')

    @property
    def chunks(self) -> Iterator[ChunkHeader]:
        raw_chunk = self._file.read(0x10000)
        while len(raw_chunk) == 0x10000:
            try:
                yield ChunkHeader(raw_chunk, 0)
            except IOError:
                pass
            raw_chunk = self._file.read(0x10000)

    @property
    def records(self) -> Iterator[Event]:
        for chunk in self.chunks:
            for record in chunk.records():
                try:
                    evt_tree: etree = record.lxml()
                except (OverrunBufferException, XMLSyntaxError, KeyError, UnicodeDecodeError):
                    _logger.warning(f'{self._file.name}: error while processing events')
                    continue
                try:
                    event = xml_to_dict(evt_tree)
                    event['carved'] = False
                except ValueError:
                    continue
                yield Event(**event)
