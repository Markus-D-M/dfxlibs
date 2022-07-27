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

from typing import TYPE_CHECKING, List
from datetime import datetime

if TYPE_CHECKING:
    from dfxlibs.windows.registry import WindowsRegistry


class NetworkInterface:
    def __init__(self, service_name: str = None, description: str = None, dhcp_ip_address: str = None,
                 ip_address: str = None, lease_obtained_time: datetime = None):
        self.service_name = service_name
        self.description = description
        self.dhcp_ip_address = dhcp_ip_address
        self.ip_address = ip_address
        self.lease_obtained_time = lease_obtained_time

    def __repr__(self):
        return (f'<{self.__class__.__name__} ' +
                ' '.join([f'{attr}={repr(self.__getattribute__(attr))}'
                          for attr in self.__dict__
                          if self.__getattribute__(attr) is not None and attr[0] != '_']) +
                ' />')


def network_interfaces(self: 'WindowsRegistry') -> List[NetworkInterface]:
    key_interfaces = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards'
    key_parameters = 'SYSTEM\\ControlSet001\\Services\\Tcpip\\Parameters\\Interfaces'
    interfaces = {}
    for interface in self._open(key_interfaces).subkeys():
        interfaces[interface.value('ServiceName').value().lower()] = \
            {'description': interface.value('Description').value(),
             'service_name': interface.value('ServiceName').value().lower()}
    values = {
        'DhcpIPAddress': ['dhcp_ip_address', lambda x: x],
        'IPAddress': ['ip_address', lambda x: x],
        'LeaseObtainedTime': ['lease_obtained_time', datetime.fromtimestamp],
    }
    for interface in self._open(key_parameters).subkeys():
        if interface.name().lower() not in interfaces:
            interfaces[interface.name().lower()] = {'service_name': interface.name().lower()}
        for config in interface.values():
            if config.name() in values:
                interfaces[interface.name()][values[config.name()][0]] = values[config.name()][1](config.value())
    return [NetworkInterface(**interfaces[ni]) for ni in interfaces]
