# coding: utf-8
"""
   create xls documents

   Copyright 2022 Markus D (mar.d@gmx.net)

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
"""

import xlsxwriter

from typing import TYPE_CHECKING, List, Optional

if TYPE_CHECKING:
    from xlsxwriter.worksheet import Worksheet
    from xlsxwriter.format import Format


class ExcelWriter:
    def __init__(self, filename: str):
        self._filename = filename
        self.workbook = xlsxwriter.Workbook(filename)
        self.sheets = dict()
        self._wb_formats = {}
        self.formats = {
            'bg-darkblue-100': {'bg_color': '#004b76', 'font_color': 'white'},
            'bg-lightorange-100': {'bg_color': '#f7bb3d'},
            'bg-yellow-60': {'bg_color': '#fbec89'},
            'bold': {'bold': True},
            'datetime': {'num_format': 'dd.mm.yyyy hh:mm:ss.000'}
        }
        self.current_row = 0
        self.current_sheet_name = 'Sheet 1'

    def get_format(self, *args) -> Optional['Format']:
        if len(args) == 0:
            return None
        final_name = '|'.join(args)
        if final_name in self._wb_formats:
            return self._wb_formats[final_name]
        else:
            final_format = {}
            for arg in args:
                try:
                    final_format.update(self.formats[arg])
                except IndexError:
                    continue
            self._wb_formats[final_name] = self.workbook.add_format(final_format)
            return self._wb_formats[final_name]

    def auto_filter(self, first_row, first_col, last_row, last_col, sheet_name: str = None):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.autofilter(first_row, first_col, last_row, last_col)

    def freeze_rows(self, row_count, sheet_name: str = None):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.freeze_panes(row_count, 0)

    def set_col_width(self, first_col: int, last_col: int, width: int, sheet_name: str = None):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.set_column(first_col, last_col, width)

    def write_cells(self, data: List[List], offset_row: int = None, offset_col: int = 0, sheet_name: str = None,
                    default_format: List[str] = []):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        if offset_row is not None:
            self.current_row = offset_row
        sheet = self._get_sheet(sheet_name)
        for row_number, row_value in enumerate(data):
            for col_number, col_data in enumerate(row_value):
                if type(col_data) == list:
                    cell_value = col_data[0]
                    cell_format = self.get_format(*default_format, col_data[1])
                else:
                    cell_value = col_data
                    cell_format = self.get_format(*default_format)

                sheet.write(self.current_row, offset_col + col_number, cell_value, cell_format)
            self.current_row += 1

    def _get_sheet(self, sheet_name: str) -> 'Worksheet':
        if sheet_name not in self.sheets:
            self.sheets[sheet_name] = self.workbook.add_worksheet(sheet_name)
        return self.sheets[sheet_name]

    def write(self, row: int, col: int, content: str, sheet_name: str = None, default_format: List[str] = []):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        cell_format = self.get_format(*default_format)
        sheet.write(row, col, content, cell_format)

    def cell_comment(self, row: int, col: int, comment: str, sheet_name: str = None):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.write_comment(row, col, comment)

    def close(self):
        self.workbook.close()
