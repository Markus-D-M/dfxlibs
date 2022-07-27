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

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from dfxlibs.windows.registry import WindowsRegistry


def windows_version(self: 'WindowsRegistry'):
    key_version = 'SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion'
    key = self._open(key_version)
    build: str = key.value('CurrentBuildNumber').value()
    product_name: str = key.value('ProductName').value()
    if int(build) >= 22000:
        product_name = product_name.replace(' 10', ' 11')
    return product_name
