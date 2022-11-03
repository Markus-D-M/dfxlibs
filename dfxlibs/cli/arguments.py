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

import argparse
import sys

from dfxlibs import __version__


class Arguments:
    def __init__(self):
        self.groups = {}
        self.group_order = []

    def add_group(self, group_id: str, title: str, description: str):
        self.group_order.append(group_id)
        self.groups[group_id] = {'title': title, 'description': description, 'actions': []}

    def add_argument(self, *args, **kwargs):
        if 'group_id' not in kwargs:
            return
        group_id = kwargs['group_id']
        del kwargs['group_id']
        self.groups[group_id]['actions'].append({'args': args, 'kwargs': kwargs})

    def get_argument_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            description=f'dfxlibs: A python digital forensics toolkit (version {__version__})')
        for group_id in self.group_order:
            group = parser.add_argument_group(title=self.groups[group_id]['title'],
                                              description=self.groups[group_id]['description'])
            for action in self.groups[group_id]['actions']:
                kw = {k: v for k, v in action['kwargs'].items() if k != 'func'}
                group.add_argument(*action['args'], **kw)
        return parser

    def execute_arguments(self):
        for ordered_arg in sys.argv:
            for group_id in self.group_order:
                for action in self.groups[group_id]['actions']:
                    if ordered_arg in action['args'] and 'func' in action['kwargs']:
                        action['kwargs']['func']()


arguments = Arguments()
arguments.add_group('general', 'General Arguments', 'These parameters are used in all categories.')
arguments.add_argument('-m', '--meta_folder', required=True, help='folder to store and load meta information',
                       group_id='general')
arguments.add_argument('--meta_create', action='store_true', help='create meta information folder if not exists',
                       group_id='general')
arguments.add_argument('-i', '--image', nargs='+', help='forensic image file. This parameter is stored in the meta '
                                                        'information folder, so it is only needed for the first call '
                                                        'on an image. If this parameter is given on proceeding calls, '
                                                        'it will overwrite the parameter in the meta information '
                                                        'folder (so be careful to not mix up different images in one '
                                                        'meta information folder).', group_id='general')
arguments.add_argument('--part', help='Specify partition for actions like --prepare_files. It must be named as given '
                                      'in the --list_partitions output. Without --part all partitions in an image will '
                                      'be included.', group_id='general')
arguments.add_group('prepare', 'Preparation', 'These arguments prepare the data from the image for further analysis')
arguments.add_group('carve', 'Carving', 'These arguments are for different carving options.')
arguments.add_group('special', 'Special actions', 'These parameters contains short and simple actions.')


def register_argument(*args, **kwargs):
    def wrap(func):
        kwargs['func'] = func
        arguments.add_argument(*args, **kwargs)
        
        def call_func(*args):
            func(*args)
        return call_func
    return wrap
