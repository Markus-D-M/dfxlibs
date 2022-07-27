# coding: utf-8
"""
    dfxlibs cli --scan_files

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
import sqlite3
import os


import dfxlibs

_logger = logging.getLogger(__name__)


def recursive_dirlist(dir_entry: dfxlibs.general.baseclasses.file.File, parents=[], db_cur: sqlite3.Cursor = None):
    for entry in dir_entry.entries:
        if entry.name == '.' or entry.name == '..':
            continue
        entry.parent_folder = '/' + '/'.join([*parents])
        try:
            db_cur.execute(*entry.db_create_insert())
        except sqlite3.IntegrityError:
            pass
        for ads in entry.ntfs_ads:
            try:
                db_cur.execute(*ads.db_create_insert())
            except sqlite3.IntegrityError:
                pass

        if entry.is_dir and entry.allocated:
            recursive_dirlist(entry, [*parents, entry.name], db_cur=db_cur)


def scan_files(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> None:
    """
    scan all files and directories in a given Image and stores them in a sqlite database in the meta_folder.
    If partition is specified then only the files and directories of this partition are scanned

    :param image: image file
    :type image: dfxlibs.general.image.Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: None
    :raise AttributeError: if image is None
    """
    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    partitions = image.partitions
    for partition in partitions:
        if part is not None and f'{partition.table_num}_{partition.slot_num}' != part:
            continue
        root = partition.get_file('/')
        sqlite_con = sqlite3.connect(os.path.join(meta_folder, f'files_{partition.table_num}_{partition.slot_num}.db'))
        sqlite_con.row_factory = dfxlibs.general.baseclasses.file.File.db_factory
        sqlite_cur = sqlite_con.cursor()
        for create_command in root.db_create_table():
            sqlite_cur.execute(create_command)
        root.name = '/'
        try:
            sqlite_cur.execute(*root.db_create_insert())
        except sqlite3.IntegrityError:
            pass
        recursive_dirlist(root, db_cur=sqlite_cur)
        sqlite_con.commit()
