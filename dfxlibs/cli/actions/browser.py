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
from typing import List
import sqlite3

import dfxlibs


def get_browser_history(image: dfxlibs.general.image.Image, meta_folder: str, part: str = None) -> List:
    """
    analysing filesystem for browser history (currently only chrome)

    :param image: image file
    :type image: dfxlibs.general.image.Image
    :param meta_folder: name of the meta information folder to store/read file database
    :type meta_folder: str
    :param part: partition name in the format "X_Y"
    :type part: str
    :return: List of browser history entries ordered by timestamp [timestamp, user, browser, url, title]
    :rtype: List
    :raise AttributeError: if image is None
    :raise IOError: if files are not scanned
    """

    if image is None:
        raise AttributeError('ERROR: No image file specified (--image)')

    partitions = image.partitions
    result = []
    for partition in partitions:
        if part is not None and f'{partition.table_num}_{partition.slot_num}' != part:
            continue
        file_db = os.path.join(meta_folder, f'files_{partition.table_num}_{partition.slot_num}.db')
        if not os.path.isfile(file_db):
            raise IOError('ERROR: No file database. Use --scan_files first')

        # Chrome
        sqlite_files_con = sqlite3.connect(file_db)
        sqlite_files_con.row_factory = dfxlibs.general.baseclasses.file.File.db_factory
        sqlite_files_cur = sqlite_files_con.cursor()
        sqlite_files_cur.execute('SELECT * FROM File WHERE name = "History" '
                                 'and parent_folder like "/Users/%/AppData/Local/Google/Chrome/User Data/Default"')

        chrome_histories = sqlite_files_cur.fetchall()
        for chrome_history in chrome_histories:
            tmp_filename = os.path.join(meta_folder, 'tmp.db')
            with open(tmp_filename, 'wb') as f:
                chrome_history.open(partition)
                f.write(chrome_history.read())
            user = chrome_history.parent_folder[7:-46]
            sqlite_chrome_con = sqlite3.connect(tmp_filename)
            sqlite_chrome_cur = sqlite_chrome_con.cursor()

            sqlite_chrome_cur.execute("select datetime((visit_time/1000000-11644473600), 'unixepoch') as timestamp, "
                                      "urls.url as url, title from visits left join urls "
                                      "on visits.url = urls.id order by timestamp")
            for history_entry in sqlite_chrome_cur.fetchall():
                result.append([history_entry[0], user, 'Chrome', history_entry[1], history_entry[2]])
            sqlite_chrome_con.close()
            os.remove(tmp_filename)

    result.sort(key=lambda x: x[0])
    result.insert(0, ['Timestamp', 'User', 'Browser', 'Url', 'Title'])
    return result
