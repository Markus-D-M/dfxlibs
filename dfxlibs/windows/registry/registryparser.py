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
import struct
from Registry import RegistryParse
from datetime import datetime, timezone
from typing import Iterator, Optional

from dfxlibs.windows.registry.registryentry import RegistryEntry

_logger = logging.getLogger(__name__)


def get_guid(data: bytes) -> str:
    return f'{{{data[0:4][::-1].hex()}-{data[4:6][::-1].hex()}-{data[6:8][::-1].hex()}-' \
           f'{data[8:10].hex()}-{data[10:].hex()}}}'.upper()


def normalize_key_path(key_path: str, mount_point: str) -> str:
    """
    Replaces the hive basename with the name of the mountpoint

    :param key_path: key name
    :param mount_point: mountpoint
    :return: path with key name replaced with the mountpoint
    """
    key_path = key_path + '\\'
    # delete hive name
    _, key_path = key_path.split('\\', 1)
    key_path = key_path.strip('\\')
    # prepend mount point
    mount_point = mount_point.strip('\\')
    path = (mount_point + '\\' + key_path).strip('\\')
    return path


def get_value_content(vk: RegistryParse.VKRecord) -> (any, str):
    content = ''
    rtype = vk.data_type_str()
    try:
        try:
            content = vk.data()
        except RegistryParse.RegistryStructureDoesNotExist:
            content = '(not exists error)'
        if rtype.startswith('Unknown'):
            raise RegistryParse.UnknownTypeException('')
    except RegistryParse.UnknownTypeException:
        raw_type = vk.data_type()
        if raw_type == 0x11:
            rtype = 'Custom:RegBool:' + str(raw_type)
            content = bool(vk.raw_data()[0])
        elif raw_type in [0x12, 0x19]:
            rtype = 'Custom:RegUnicode:' + str(raw_type)
            content = RegistryParse.decode_utf16le(vk.raw_data())
        elif raw_type == 0x82:
            rtype = 'Custom:RegMultiUnicode:' + str(raw_type)
            content = vk.raw_data().decode('utf16').split('\0')
        elif raw_type == 0x0d:
            rtype = 'Custom:RegGuid:' + str(raw_type)
            raw_data = vk.raw_data()
            content = get_guid(raw_data)
        else:
            rtype = 'Custom:Unknown:' + str(raw_type)
    except UnicodeDecodeError:
        pass

    if type(content) is bytes:
        content = content.hex()
    elif type(content) is datetime:
        try:
            content = content.timestamp()
        except OSError:
            content = content.isoformat()

    return content, rtype


def _rebuild_key_path(key: RegistryParse.NKRecord, mount_point: str, recovered: bool = False) -> str:
    p = key
    parent_keys = [key]
    offsets = {p._offset}
    while p.has_parent_key():
        p = p.parent_key()
        if p._offset in offsets:
            break
        parent_keys.append(p)
        offsets.add(p._offset)

    full_path = '\\'.join([k.name() for k in reversed(parent_keys)])
    if parent_keys[-1].is_root():
        path = normalize_key_path(full_path, mount_point)
    elif recovered:
        path = mount_point + '\\[PARENT_UNKNOWN]\\' + full_path
    else:
        _logger.warning(f'Cannot reconstruct path from {key.name()} in {mount_point}')
        path = ''
    return path


def walk_registry(key: RegistryParse.NKRecord, mount_point: str = None, recovered: bool = False) \
        -> Iterator[RegistryEntry]:
    queue = [key]

    while len(queue) > 0:
        key = queue.pop(0)

        # build full key path
        try:
            path = _rebuild_key_path(key, mount_point, recovered)
        except (UnicodeDecodeError, struct.error):
            if recovered:
                # Broken key
                continue
            else:
                raise

        try:
            parent, name = path.rsplit('\\', 1)
        except ValueError:
            parent = '\\'
            name = path

        # key class
        classname = ''
        try:
            if key.has_classname():
                classname = key.classname()
        except (struct.error, UnicodeDecodeError) as e:
            if not recovered:
                _logger.warning(f'Error while parsing key from {path}/{name}: {str(e)}')
            else:
                continue

        # key default value (value name == "")
        try:
            value: Optional[RegistryParse.VKRecord] = None
            for v in key.values_list().values():
                try:
                    if v.name() == '':
                        value = v
                        break
                except UnicodeDecodeError:
                    continue
            if value is None:
                raise RegistryParse.RegistryStructureDoesNotExist('')
            raw_content = value.raw_data().hex()
            try:
                timestamp = key.timestamp().replace(tzinfo=timezone.utc)
            except OverflowError:
                if recovered:
                    # Broken key
                    continue
                raise
            content, rtype = get_value_content(value)
        except (RegistryParse.ParseException, RegistryParse.RegistryStructureDoesNotExist, struct.error, IndexError):
            rtype = 'RegSZ'
            content = '(value not set)'
            raw_content = ''
            try:
                timestamp = key.timestamp().replace(tzinfo=timezone.utc)
            except OverflowError:
                timestamp = datetime.fromtimestamp(0, tz=timezone.utc)

        regentry = RegistryEntry(timestamp=timestamp,
                                 parent_key=parent,
                                 name=name,
                                 rtype=rtype,
                                 raw_content=raw_content,
                                 parsed_content=content,
                                 is_key=True,
                                 classname=classname,
                                 deleted=recovered)

        yield regentry

        # values
        timestamp = datetime.fromtimestamp(0, tz=timezone.utc)
        if key.values_number() > 0:
            try:
                gen_values = key.values_list().values()
                while True:
                    try:
                        value = next(gen_values)
                    except StopIteration:
                        break
                    except (RegistryParse.ParseException, struct.error) as e:
                        if not recovered:
                            _logger.warning(f'Error while parsing value from {path}/{name}: {str(e)}')
                        continue

                    if recovered:
                        # if recovering then only values from free cells
                        d = RegistryParse.HBINCell(value._buf, value.offset() - 4, False)
                        if not d.is_free():
                            continue
                    try:
                        name = value.name()
                    except UnicodeDecodeError:
                        name = '(decode error)'
                    if name == '':
                        continue
                    try:
                        raw_content = value.raw_data().hex()
                    except RegistryParse.RegistryStructureDoesNotExist:
                        raw_content = '(not exists error)'
                    content, rtype = get_value_content(value)

                    regentry = RegistryEntry(timestamp=timestamp,
                                             parent_key=path,
                                             name=name,
                                             rtype=rtype,
                                             parsed_content=content,
                                             raw_content=raw_content,
                                             is_key=False,
                                             deleted=recovered)

                    yield regentry
            except struct.error as e:
                if not recovered:
                    _logger.warning(f'Error while parsing values from {path}/{name}: {str(e)}')

        if key.subkey_number() > 0:
            try:
                gen_subkeys = key.subkey_list().keys()
                while True:
                    try:
                        subkey = next(gen_subkeys)
                        queue.append(subkey)
                    except StopIteration:
                        break
                    except RegistryParse.ParseException as e:
                        _logger.warning(f'Error while parsing subkey from {path}/{name}: {str(e)}')
            except (struct.error, RegistryParse.ParseException) as e:
                if not recovered:
                    _logger.warning(f'Error while parsing subkeys from {path}/{name}: {str(e)}')


def recover_keys(hive_reg: RegistryParse.REGFBlock, mount_point: str) -> Iterator['RegistryEntry']:
    for HBIN in hive_reg.hbins():
        for cell in HBIN.cells():
            if cell.is_free():
                # carve cells
                offset, data_size = cell.data_offset(), cell.size()
                first_offset = offset
                while offset <= first_offset + data_size - 0x4a:
                    if hive_reg._buf[offset:offset + 2] == b'nk':
                        nk = RegistryParse.NKRecord(hive_reg._buf, offset, cell)
                        for reg_entry in walk_registry(nk, mount_point, recovered=True):
                            yield reg_entry
                    offset += 4


def parse_registry(hive_buf: bytes, mount_point: str) -> Iterator['RegistryEntry']:
    hive_reg = RegistryParse.REGFBlock(hive_buf, 0, False)

    for reg_entry in walk_registry(hive_reg.first_key(), mount_point):
        yield reg_entry

    for reg_entry in recover_keys(hive_reg, mount_point):
        yield reg_entry
