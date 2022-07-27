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

from lxml import etree
from datetime import datetime, timezone
from re import findall
from base64 import b64decode
from typing import Union, Optional
import re


def __safe_tag_read(tree: etree, tag_name: str, result_type: type = str,
                    attrib: Optional[str] = None, namespaces: str = None) -> Union[str, int]:
    try:
        if attrib is None:
            return result_type(tree.find(tag_name, namespaces=namespaces).text)
        else:
            return result_type(tree.find(tag_name, namespaces=namespaces).attrib[attrib])
    except (AttributeError, TypeError):
        if result_type is str:
            return ''
        elif result_type is int:
            return -1


def xml_to_dict(evt_tree) -> dict:
    namespace = evt_tree.nsmap
    event = {}
    system_tag = evt_tree.find('System', namespaces=namespace)
    event['event_id'] = __safe_tag_read(system_tag, 'EventID', result_type=int, namespaces=namespace)
    event['channel'] = __safe_tag_read(system_tag, 'Channel', namespaces=namespace)
    event['event_record_id'] = __safe_tag_read(system_tag, 'EventRecordID', result_type=int, namespaces=namespace)
    event['opcode'] = __safe_tag_read(system_tag, 'Opcode', result_type=int, namespaces=namespace)
    event['level'] = __safe_tag_read(system_tag, 'Level', result_type=int, namespaces=namespace)
    event['computer'] = __safe_tag_read(system_tag, 'Computer', namespaces=namespace)
    event['user_id'] = __safe_tag_read(system_tag, 'Security', attrib='UserID', namespaces=namespace)
    event['provider'] = __safe_tag_read(system_tag, 'Provider', attrib='Name', namespaces=namespace)
    event_tag = evt_tree.find('EventData', namespaces=namespace)
    if event_tag is None:
        event_tag = evt_tree.find('UserData', namespaces=namespace)
        if event_tag is not None:
            event_tag = event_tag.getchildren()[0]
    try:
        event['timestamp'] = datetime.strptime(__safe_tag_read(system_tag, 'TimeCreated',
                                                               attrib='SystemTime', namespaces=namespace),
                                               '%Y-%m-%d %H:%M:%S.%f').replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            event['timestamp'] = datetime.strptime(__safe_tag_read(system_tag, 'TimeCreated',
                                                                   attrib='SystemTime', namespaces=namespace),
                                                   '%Y-%m-%d %H:%M:%S').replace(tzinfo=timezone.utc)
        except ValueError:
            raise ValueError('No valid timestamp')

    if event['timestamp'].year < 1970:
        raise ValueError('No valid timestamp')

    event['data'] = {}
    if event_tag is not None:
        data_list = []
        for data in event_tag.getchildren():
            try:
                event['data'][data.attrib['Name']] = data.text
            except KeyError:
                if data.text is not None:
                    _, data_tag = data.tag.split('}', 1)
                    if data_tag == 'Data':
                        finds = findall('<.+?>(.*?)</.+?>', data.text, re.DOTALL)
                        if finds:
                            data_list += finds
                        else:
                            data_list.append(data.text)
                    elif data_tag == 'Binary':
                        data_list.append(b64decode(data.text).hex())
                    else:
                        event['data'][data_tag] = data.text
        event['data'].update({k: v for k, v in enumerate(data_list)})
    return event
