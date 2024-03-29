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

import os
import glob
import importlib

# Dynamic import all under ./actions incl. subdirectories

__filedir__ = os.path.dirname(os.path.realpath(__file__))
for file in glob.glob(os.path.join(__filedir__, '**', '[!_]*.py'), recursive=True):
    module = file.replace(__filedir__, '').replace('.py', '').replace(os.path.sep, '.')
    importlib.import_module(__name__ + module)
