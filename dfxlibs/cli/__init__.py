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
from os.path import isdir, join
from os import makedirs, mkdir
import glob
import sys
import logging
import datetime
from typing import List, Dict
from json import dumps, loads, JSONDecodeError


import dfxlibs

from dfxlibs.cli import actions, environment

__all__ = ['actions', 'environment']

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
            makedirs(folder, exist_ok=True)
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
    group_general = parser.add_argument_group('General Arguments', 'These parameters are used in all categories.')
    group_general.add_argument('-m', '--meta_folder', required=True,
                               help='folder to store and load meta information')
    group_general.add_argument('--meta_create', action='store_true',
                               help='create meta information folder if not exists')
    group_general.add_argument('-i', '--image', nargs='+',
                               help='forensic image file. This parameter is stored in the meta information folder, so '
                                    'it is only needed for the first call on an image. If this parameter is given on '
                                    'proceeding calls, it will overwrite the parameter in the meta information folder '
                                    '(so be careful to not mix up different images in one meta information folder).')
    group_general.add_argument('--part',
                               help='Specify partition for actions like --scan_files. It must be named as given in the '
                                    '--list_partitions output. Without --part all partitions in an image will be '
                                    'included.')
    group_preparation = parser.add_argument_group('Preparation', 'These arguments prepare the data from the image for '
                                                                 'further analysis')
    group_preparation.add_argument('-pf', '--prepare_files', action='store_true',
                                   help='Scan files and directories of all partitions. You can specify a partition '
                                        'with --part. The file entries will be stored in the meta_folder in a sqlite '
                                        'database')
    group_preparation.add_argument('-pvss', '--prepare_vss', action='store_true',
                                   help='Scan for files and directories in volume shadow copies of all partitions. '
                                        'You can specify a partition with --part. The file entries will be stored in '
                                        'the meta_folder in a sqlite database')
    group_preparation.add_argument('--hash', nargs='+',
                                   help='Hash all files <256 MiB of all partitions. You can specify a partition '
                                        'with --part. Possible algorithms are md5, sha1, sha256 and tlsh. A minimum '
                                        'filesize of 50 bytes is required for tlsh. The result is stored in the file '
                                        'database.')
    group_preparation.add_argument('--filetypes', action='store_true',
                                   help='turn on signature based detection of filetypes of all files in all '
                                        'partitions. The result is stored in the file database.'
                                        'You can specify a partition  with --part. ')
    group_preparation.add_argument('-pevtx', '--prepare_evtx', action='store_true',
                                   help='read all windows evtx logs in a given Image and stores them in a sqlite '
                                        'database in the meta_folder.  You can specify a partition with --part. ')
    group_preparation.add_argument('-preg', '--prepare_reg', action='store_true',
                                   help='read the windows registry and stores them in a sqlite database in the '
                                        'meta_folder. You can specify a partition with --part.')
    group_preparation.add_argument('-pusn', '--prepare_usn', action='store_true',
                                   help='reading ntfs usn journals ans stores the entries in a sqlite database in the '
                                        'meta_folder. You can specify a partition with --part.')

    group_carve = parser.add_argument_group('Carving', 'These arguments are for different carving options.')
    group_carve.add_argument('-cevtx', '--carve_evtx', action='store_true', help='carve for windows evtx entries and '
                                                                                 'stores them in the same database as '
                                                                                 'for the --prepare_evtx argument')
    group_carve.add_argument('-cusn', '--carve_usn', action='store_true', help='carve for ntfs usn journal entries and '
                                                                               'stores them in the same database as '
                                                                               'for the --prepare_usn argument')

    group_actions = parser.add_argument_group('Special actions', 'These parameters contains short and simple actions.')
    group_actions.add_argument('-lp', '--list_partitions', action='store_true',
                               help='print partition list')
    group_actions.add_argument('-e', '--extract', nargs='+',
                               help='Extracts files from the image and stores them to the meta_folder. You have to '
                                    'give the full path and filename (with leading slash - even slashes instead of '
                                    'backslashes for windows images) or a meta address. As default source "filesystem" '
                                    'for regular files in the image will be used. You can give another filesource '
                                    '(e.g. "vss#0" for shadow copy store 0) by just adding it in front of your path '
                                    'and separate it with a colon (e.g. "vss#0:/path/testfile.txt" for '
                                    '/path/testfile.txt from vss#0). You can give multiple files at once')

    parser.add_argument('-a', '--analyze', nargs='+', help='Analyze prepared data. Possible values are: '
                                                           '"sessions" list user sessions'
                                                           '"browser_history" scans chrome history')

    return parser.parse_args()


def main():
    env = environment.Environment(args=parse_arguments(), meta_folder='', config={}, image=None)

    try:
        meta_folder(env)
    except IOError as e:
        print(e)
        sys.exit(1)

    _logger.info('Running ' + ' '.join(sys.argv))
    _logger.info(f'dfxlibs version: {dfxlibs.__version__}')

    if image_files := get_image_files(env):
        env['image'] = dfxlibs.general.image.Image(image_files)
        _logger.info(f'using image: {image_files}')

    if env['args'].list_partitions:
        try:
            dfxlibs.cli.actions.partitions.list_partitions(env['image'])
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].extract:
        try:
            dfxlibs.cli.actions.files.extract(env['image'], meta_folder=env['meta_folder'],
                                              part=env['args'].part, files=env['args'].extract)
        except AttributeError as e:
            print(e)
            sys.exit(2)


    if env['args'].prepare_files:
        try:
            dfxlibs.cli.actions.files.prepare_files(env['image'], meta_folder=env['meta_folder'],
                                                    part=env['args'].part)
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].prepare_vss:
        try:
            dfxlibs.cli.actions.files.prepare_vss_files(env['image'], meta_folder=env['meta_folder'],
                                                        part=env['args'].part)
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].hash:
        try:
            dfxlibs.cli.actions.files.hash_files(env['image'], meta_folder=env['meta_folder'],
                                                 part=env['args'].part, hash_algorithms=env['args'].hash)
        except AttributeError as e:
            print(e)
            sys.exit(2)

    if env['args'].filetypes:
        try:
            dfxlibs.cli.actions.files.file_types(env['image'], meta_folder=env['meta_folder'],
                                                 part=env['args'].part)
        except AttributeError as e:
            print(e)
            sys.exit(2)
    if env['args'].prepare_usn:
        try:
            dfxlibs.cli.actions.usnjournal.prepare_usnjournal(env['image'], meta_folder=env['meta_folder'],
                                                              part=env['args'].part)
        except (AttributeError, IOError, ValueError) as e:
            print(e)
            sys.exit(2)
    if env['args'].carve_usn:
        try:
            dfxlibs.cli.actions.usnjournal.carve_usnjournal(env['image'], meta_folder=env['meta_folder'],
                                                            part=env['args'].part)
        except (AttributeError, IOError) as e:
            print(e)
            sys.exit(2)

    if env['args'].prepare_evtx:
        try:
            dfxlibs.cli.actions.events.prepare_evtx(env['image'], meta_folder=env['meta_folder'],
                                                    part=env['args'].part)
        except (AttributeError, IOError) as e:
            print(e)
            sys.exit(2)
    if env['args'].carve_evtx:
        try:
            dfxlibs.cli.actions.events.carve_evtx(env['image'], meta_folder=env['meta_folder'],
                                                  part=env['args'].part)
        except (AttributeError, IOError) as e:
            print(e)
            sys.exit(2)
    if env['args'].prepare_reg:
        try:
            dfxlibs.cli.actions.registry.prepare_registry(env['image'], meta_folder=env['meta_folder'],
                                                          part=env['args'].part)
        except (AttributeError, IOError) as e:
            print(e)
            sys.exit(2)
    if env['args'].analyze:
        results = {}
        if 'sessions' in env['args'].analyze:
            results['sessions'] = dfxlibs.cli.actions.events.get_user_sessions(
                env['image'], meta_folder=env['meta_folder'], part=env['args'].part)
        if 'browser_history' in env['args'].analyze:
            results['browser_history'] = dfxlibs.cli.actions.browser.get_browser_history(
                env['image'], meta_folder=env['meta_folder'], part=env['args'].part)

        # output results:
        fname_results = join(env['meta_folder'],
                             datetime.datetime.utcnow().strftime('%Y-%m-%d_%H-%M-%S') + '_analyze.xlsx')
        writer = dfxlibs.general.helpers.ExcelWriter(fname_results)
        for sheet in results:
            writer.write_cells([results[sheet][0]], sheet_name=sheet, offset_col=1, offset_row=1,
                               default_format=['bg-darkblue-100', 'bold'])
            writer.write_cells(results[sheet][1:], sheet_name=sheet, offset_col=1, offset_row=2)
            writer.auto_filter(1, 1, writer.current_row,  len(results[sheet][0]), sheet_name=sheet)

        writer.close()


if __name__ == '__main__':
    main()
