# coding: utf-8
"""
    dfxlibs commandline tool

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
from os.path import isdir, join, isfile
from os import mkdir
import glob
import sys
import logging
import datetime
from typing import List, Dict
from json import dumps, loads, JSONDecodeError

import dfxlibs

from dfxlibs.cli import actions

__all__ = ['actions']

LOGGING_FORMAT = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S%z",
                    level=logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter(LOGGING_FORMAT, "%Y-%m-%dT%H:%M:%S%z"))
_logger = logging.getLogger('dfxlibs.cli')


def change_log_handler(filename: str = None):
    """
    Change loghandler to stdout and filename (if given).

    :param filename: log filename
    :type filename: str
    """
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    root_logger.addHandler(stream_handler)
    if filename is not None:
        file_log_handler = logging.FileHandler(filename)
        file_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT, "%Y-%m-%dT%H:%M:%S%z"))
        root_logger.addHandler(file_log_handler)


def get_image_files(env: Dict) -> List[str]:
    """
    Get list of image files.
    Sources are metafolder config or commandline params.
    If image files are given via commandline parameters, the result is stored at the metafolder config.

    :param env: cli environment
    :type env: dict
    :return: List of image files
    :rtype: list
    """
    args: argparse.Namespace = env['args']
    if args.image is None:
        try:
            image_files = env['config']['image_files']
        except KeyError:
            image_files = []
        return image_files
    elif len(args.image) == 1 and '*' in args.image[0]:
        image_files = [f for f in glob.glob(args.image[0]) if f[-4:].lower() not in ['.txt', '.pdf', 'html', '.xml']]
        env['config']['image_files'] = image_files
    else:
        image_files = args.image
        env['config']['image_files'] = image_files
    with open(join(env['meta_folder'], 'config.json'), 'w') as f:
        f.write(dumps(env['config']))
    return image_files


def meta_folder(env: Dict):
    """
    Check existence of meta information folder.
    Create folder if needed and --meta_create flag is set.
    Logs are stored to a 'logs' subfolder of the meta information folder.
    Metafolder name is stored in env['meta_folder'].
    Config from metafolder is stored in env['config'].

    :param env: cli environment
    :type env: dict
    :raise IOError: if meta_folder does not exist and --meta_create flag is not set.
    """
    args: argparse.Namespace = env['args']
    folder = args.meta_folder
    if not isdir(folder):
        if args.meta_create:
            mkdir(folder)
        else:
            raise IOError(f'ERROR: Meta information folder {repr(folder)} does not exist. '
                          'Use --meta_create flag or create it manually')
    if not isdir(join(folder, 'logs')):
        mkdir(join(folder, 'logs'))
    change_log_handler(join(folder, 'logs', f'{datetime.date.today().strftime("%Y-%m-%d")}_log.txt'))
    env['meta_folder'] = folder
    try:
        with open(join(env['meta_folder'], 'config.json'), 'r') as f:
            env['config'] = loads(f.read())
    except (FileNotFoundError, JSONDecodeError):
        env['config'] = {}


def parse_arguments():
    parser = argparse.ArgumentParser(description='dfxlibs: A python digital forensics toolkit')
    parser.add_argument('-m', '--meta_folder', required=True, help='folder to store and load meta information')
    parser.add_argument('--meta_create', action='store_true', help='create meta information folder if not exists')
    parser.add_argument('-i', '--image', nargs='+', help='forensic image file')
    parser.add_argument('-lp', '--list_partitions', action='store_true', help='print partition list')
    parser.add_argument('-sf', '--scan_files', action='store_true', help='Scan files and directories of all partitions.'
                                                                         ' You can specify a partition with '
                                                                         '--part. The file entries will be stored '
                                                                         'in the meta_folder in a sqlite database')
    parser.add_argument('-cevtx', '--convert_evtx', action='store_true', help='read all windows evtx logs in a given '
                                                                              'Image and stores them in a sqlite '
                                                                              'database in the meta_folder.'
                                                                              ' You can specify a partition with '
                                                                              '--part.')
    parser.add_argument('--part', help='Specify partition for actions like --scan_files. It must be named as '
                                       'given in the --list_partitions output.')
    return parser.parse_args()


def main():
    env = dict()

    env['args'] = parse_arguments()

    try:
        meta_folder(env)
    except IOError as e:
        print(e)
        sys.exit(1)

    _logger.info('Running ' + ' '.join(sys.argv))
    _logger.info(f'dfxlibs version: {dfxlibs.__version__}')

    env['image'] = None
    if image_files := get_image_files(env):
        env['image'] = dfxlibs.general.image.Image(image_files)

    if env['args'].list_partitions:
        try:
            dfxlibs.cli.actions.partitions.list_partitions(env['image'])
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].scan_files:
        try:
            dfxlibs.cli.actions.files.scan_files(env['image'], meta_folder=env['meta_folder'],
                                                 part=env['args'].part)
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].convert_evtx:
        try:
            dfxlibs.cli.actions.events.convert_evtx(env['image'], meta_folder=env['meta_folder'],
                                                    part=env['args'].part)
        except (AttributeError, IOError) as e:
            print(e)
            sys.exit(2)



if __name__ == '__main__':
    main()
