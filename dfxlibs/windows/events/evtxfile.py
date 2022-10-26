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
from io import BytesIO
from typing import Iterator, Union
from Evtx.Evtx import ChunkHeader
import dfxlibs
from lxml import etree
from lxml.etree import XMLSyntaxError
from .xml_to_dict import xml_to_dict
from .event import Event
from Evtx.BinaryParser import OverrunBufferException, ParseException
import pyevtx
import re

RE_REMOVE_NAMESPACES = re.compile(r'([< /])[a-zA-Z]+:')

_logger = logging.getLogger(__name__)

logging.getLogger("Evtx").setLevel(logging.ERROR)

EVTX_CARVER_OFFSET_STEP = 512


def evtx_carver(current_data: bytes, current_offset: int) -> Iterator[Union[int, 'EvtxFile']]:
    """
    Carving function for evtx records in data buffers.

    :param current_data: data buffer
    :type current_data: bytes
    :param current_offset: current offset in the data buffer to analyse
    :type current_offset: int
    :return: Iterator for carved evtx record or next offset to carve
    """
    try:
        candidate_offset = current_data.index(b'ElfChnk\0', current_offset, -64*1024)
    except ValueError:
        yield len(current_data)-64*1024 + EVTX_CARVER_OFFSET_STEP
        return

    if candidate_offset % 512 != 0:
        yield candidate_offset - candidate_offset % EVTX_CARVER_OFFSET_STEP + EVTX_CARVER_OFFSET_STEP
        return

    current_offset = candidate_offset

    if current_data[current_offset:current_offset + 8] != b'ElfChnk\0' or \
            current_data[current_offset + 40] != 128 or \
            current_data[current_offset + 512:current_offset + 516] != b'**\0\0':
        yield current_offset + EVTX_CARVER_OFFSET_STEP
        return

    chunk = ChunkHeader(current_data, current_offset)
    for record in chunk.records():
        try:
            evt_tree: etree = record.lxml()
        except (OverrunBufferException, UnicodeDecodeError, KeyError, ParseException,
                XMLSyntaxError, AttributeError, IndexError, RecursionError):
            # Parse errors for partial destroyed chunks -> ignore records
            continue
        # remove namespaces
        for element in evt_tree.xpath("descendant-or-self::*[namespace-uri()!='']"):
            element.tag = etree.QName(element).localname
        etree.cleanup_namespaces(evt_tree)

        try:
            event = xml_to_dict(evt_tree)
            event['carved'] = True
        except (ValueError, IndexError):
            continue
        yield Event(**event)
    yield current_offset + EVTX_CARVER_OFFSET_STEP


class EvtxFile:
    def __init__(self, file: dfxlibs.general.baseclasses.file.File):
        self._file = file
        try:
            if not pyevtx.check_file_signature_file_object(file):
                raise IOError('Not a windows event file')
        except IOError:
            raise IOError('Not a windows event file')
        try:
            self._evtx: pyevtx.file = pyevtx.open_file_object(file)
        except IOError:
            raise IOError('Not a windows event file')

        """        if self._file.size < 4096:
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
            raw_chunk = self._file.read(0x10000)"""

    @property
    def records(self) -> Iterator[Event]:
        record: pyevtx.record
        for record in self._evtx.records:
            try:
                # ignore XML parsing errors while reading
                parser = etree.XMLParser(recover=True)
                evt_tree = etree.parse(BytesIO(record.xml_string.encode('utf-8')), parser)

                # remove namespaces
                for element in evt_tree.xpath("descendant-or-self::*[namespace-uri()!='']"):
                    element.tag = etree.QName(element).localname
                etree.cleanup_namespaces(evt_tree)

                event = xml_to_dict(evt_tree)
            except:
                print (record.xml_string)
                print(etree.tostring(evt_tree))
                raise
            event['carved'] = False
            yield Event(**event)

        """for chunk in self.chunks:
            for record in chunk.records():
                try:
                    evt_tree: etree = record.lxml()
                except (OverrunBufferException, UnicodeDecodeError, KeyError, ParseException, XMLSyntaxError,
                        AttributeError, IndexError, RecursionError):
                    raise
                    _logger.warning(f'{self._file.name}: error while processing events')
                    continue
                try:
                    event = xml_to_dict(evt_tree)
                    event['carved'] = False
                except ValueError:
                    _logger.warning(f'{self._file.name}: error while processing events')
                    continue
                yield Event(**event)
        """
