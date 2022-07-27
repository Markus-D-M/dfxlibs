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

from typing import TYPE_CHECKING, Union, List
from Registry import Registry


if TYPE_CHECKING:
    from dfxlibs.general.baseclasses.file import File


class WindowsRegistry:
    from .attributes.network_interfaces import network_interfaces
    from .attributes.users import users
    from .attributes.windows_version import windows_version

    def __init__(self, files: Union['File', List['File']]):
        if type(files) is not list:
            files = [files]
        self._reg = dict()
        for file in files:
            self._reg[file.name] = Registry.Registry(file)

    def _open(self, path: str):
        hive, path = path.split('\\', 1)
        return self._reg[hive].open(path)
