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
from dfxlibs.general.helpers.excelwriter import ExcelWriter, ExcelTable

from dfxlibs.cli import actions, environment, arguments

__all__ = ['actions', 'environment']

LOGGING_FORMAT = '%(asctime)s %(name)s [%(levelname)s] %(message)s'
logging.basicConfig(format=LOGGING_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S%z",
                    level=logging.INFO)
stream_handler = logging.StreamHandler()
stream_handler.setFormatter(logging.Formatter(LOGGING_FORMAT, "%Y-%m-%dT%H:%M:%S%z"))
_logger = logging.getLogger('dfxlibs.cli')


def change_log_handler(filename: str = None, no_stdout=False):
    """
    Change loghandler to stdout and filename (if given).

    :param filename: log filename
    :param no_stdout: if True, no output to stdout
    :type filename: str
    """
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    if not no_stdout:
        root_logger.addHandler(stream_handler)
    if filename is not None:
        file_log_handler = logging.FileHandler(filename)
        file_log_handler.setFormatter(logging.Formatter(LOGGING_FORMAT, "%Y-%m-%dT%H:%M:%S%z"))
        root_logger.addHandler(file_log_handler)


def get_image_files() -> List[str]:
    """
    Get list of image files.
    Sources are metafolder config or commandline params.
    If image files are given via commandline parameters, the result is stored at the metafolder config.

    :return: List of image files
    :rtype: list
    """
    args: argparse.Namespace = environment.env['args']
    if args.image is None:
        try:
            image_files = environment.env['config']['image_files']
        except KeyError:
            image_files = []
        return image_files
    elif len(args.image) == 1 and '*' in args.image[0]:
        image_files = [f for f in glob.glob(args.image[0]) if f[-4:].lower() not in ['.txt', '.pdf', 'html', '.xml',
                                                                                     'xmet']]
        environment.env['config']['image_files'] = image_files
    else:
        image_files = args.image
        environment.env['config']['image_files'] = image_files
    with open(join(environment.env['meta_folder'], 'config.json'), 'w') as f:
        f.write(dumps(environment.env['config']))
    return image_files


def meta_folder():
    """
    Check existence of meta information folder.
    Create folder if needed and --meta_create flag is set.
    Logs are stored to a 'logs' subfolder of the meta information folder.
    Metafolder name is stored in env['meta_folder'].
    Config from metafolder is stored in env['config'].

    :raise IOError: if meta_folder does not exist and --meta_create flag is not set.
    :raise AttributeError: if meta_folder is not given
    """
    args: argparse.Namespace = environment.env['args']
    if args.meta_folder:
        meta = args.meta_folder
        if not isdir(meta):
            if args.meta_create:
                makedirs(meta, exist_ok=True)
            else:
                raise IOError(f'ERROR: Meta information folder {repr(meta)} does not exist. '
                              'Use --meta_create flag or create it manually')
        folders = [meta]
    elif args.scan_dir:
        scan = args.scan_dir
        if not isdir(scan):
            raise IOError(f'ERROR: Scan folder {repr(scan)} does not exist. ')
        folders = []
        candidates = glob.glob(scan+'/**/config.json', recursive=True)
        for candidate in candidates:
            with open(candidate, 'r') as f:
                data = f.read()
            if data.startswith('{"image_files": ['):
                folders.append(candidate.replace('config.json', ''))
    else:
        raise AttributeError()

    for folder in folders:
        if not isdir(join(folder, 'logs')):
            mkdir(join(folder, 'logs'))
        change_log_handler(join(folder, 'logs', f'{datetime.date.today().strftime("%Y-%m-%d")}_log.txt'),
                           no_stdout=len(folders) > 1)
        environment.env['meta_folder'] = folder
        try:
            with open(join(environment.env['meta_folder'], 'config.json'), 'r') as f:
                environment.env['config'] = loads(f.read())
        except (FileNotFoundError, JSONDecodeError):
            environment.env['config'] = {}
        yield folder


"""def parse_arguments():
    parser = argparse.ArgumentParser(description='dfxlibs: A python digital forensics toolkit')

    parser.add_argument('-a', '--analyze', nargs='+', help='Analyze prepared data. Possible values are: '
                                                           '"sessions" list user sessions'
                                                           '"browser_history" scans chrome history')
    parser = arguments.arguments.get_argument_parser()
    return parser.parse_args()
"""


def main():
    environment.env['args'] = arguments.arguments.get_argument_parser().parse_args()

    try:
        for _ in meta_folder():
            _logger.info('Running ' + ' '.join(sys.argv))
            _logger.info(f'dfxlibs version: {dfxlibs.__version__}')
            if image_files := get_image_files():
                environment.env['image'] = dfxlibs.general.image.Image(image_files)
                _logger.info(f'using image: {image_files}')

            try:
                arguments.arguments.execute_arguments()
            except Exception as e:
                print(e)
                sys.exit(3)

            if environment.env['results']:
                makedirs(join(environment.env['meta_folder'], 'reports'), exist_ok=True)
                filename = join(environment.env['meta_folder'], 'reports',
                                datetime.datetime.now().strftime('%Y%m%d_%H%M%S') + '_report.xlsx')
                _logger.info(f'Writing analysis report to {filename}')
                result_file = ExcelWriter(filename)
                for result_sheet in environment.env['results']:
                    result_data = environment.env['results'][result_sheet]
                    result_file.add_sheet(result_sheet, result_data)

                result_file.close()

    except IOError as e:
        print(e)
        sys.exit(1)
    except AttributeError:
        print("dfxlibs: error: the following arguments are required: -m / --meta_folder or -s / --scan_folder")
        sys.exit(2)


if __name__ == '__main__':
    main()
