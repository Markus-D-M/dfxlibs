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
import datetime

import xlsxwriter

from typing import TYPE_CHECKING, List, Optional, Union

if TYPE_CHECKING:
    from xlsxwriter.worksheet import Worksheet
    from xlsxwriter.format import Format


class ExcelWriter:
    def __init__(self, filename: str):
        self._filename = filename
        self.workbook = xlsxwriter.Workbook(filename)
        self.workbook.remove_timezone = True
        self.sheets = dict()
        self._wb_formats = {}
        self.formats = {
            'bg-darkblue-100': {'bg_color': '#004b76', 'font_color': 'white'},
            'bg-lightorange-100': {'bg_color': '#f7bb3d'},
            'bg-yellow-60': {'bg_color': '#fbec89'},
            'bold': {'bold': True},
            'title': {'bold': True, 'font_size': 18},
            'description': {'text_wrap': True, 'valign': 'vcenter'},
            'datetime': {'num_format': 'yyyy-mm-dd hh:mm:ss.000', 'align': 'left'},
            'timedelta': {'num_format': '[h]:mm:ss', 'align': 'left'}
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

    def auto_filter(self, first_row: int, first_col: int, last_row: int, last_col: int, sheet_name: str = None):
        """
        Creates an autofilter for a area with the given dimensions

        :param first_row: first row of the area (zero indexed)
        :type first_row: int
        :param first_col: first column of the area (zero indexed)
        :type first_col: int
        :param last_row: last row of the area (zero indexed)
        :type last_row: int
        :param last_col: last column of the area (zero indexed)
        :type last_col: int
        :param sheet_name: name of the sheet
        :type sheet_name: str
        :return:
        """
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
                    default_format: List[str] = None):
        if default_format is None:
            default_format = []
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        if offset_row is not None:
            self.current_row = offset_row
        sheet = self._get_sheet(sheet_name)
        for row_number, row_value in enumerate(data):
            for col_number, col_data in enumerate(row_value):
                if type(col_data) == list:
                    cell_value = col_data[0]
                    cell_format = [*default_format, col_data[1]]
                else:
                    cell_value = col_data
                    cell_format = default_format

                self.write(self.current_row, offset_col + col_number, cell_value, sheet_name=sheet_name,
                           default_format=cell_format)
            self.current_row += 1

    def _get_sheet(self, sheet_name: str) -> 'Worksheet':
        if sheet_name not in self.sheets:
            self.sheets[sheet_name] = self.workbook.add_worksheet(sheet_name)
        return self.sheets[sheet_name]

    def write(self, row: int, col: int, content: any, sheet_name: str = None, default_format: List[str] = []):
        """
        writes content to a cell

        :param row: row to write (zero indexed)
        :type row: int
        :param col: col to write (zero indexed)
        :type col: int
        :param content: content to write
        :type content: any
        :param sheet_name: name of the sheet
        :type sheet_name: str
        :param default_format: format for the cell
        :type default_format: List[str]
        :return:
        """
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        if type(content) is datetime.datetime:
            cell_format = self.get_format(*default_format, 'datetime')
        elif type(content) is datetime.timedelta:
            cell_format = self.get_format(*default_format, 'timedelta')
        else:
            cell_format = self.get_format(*default_format)
        sheet.write(row, col, content, cell_format)

    def cell_comment(self, row: int, col: int, comment: str, sheet_name: str = None):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.write_comment(row, col, comment)

    def merge_write(self, first_row: int, first_col: int, last_row: int, last_col: int, content: any,
                    sheet_name: str = None, default_format: List[str] = []):
        if sheet_name is None:
            sheet_name = self.current_sheet_name
        sheet = self._get_sheet(sheet_name)
        sheet.merge_range(first_row, first_col, last_row, last_col, content, self.get_format(*default_format))

    def _add_excel_table(self, content: 'ExcelTable', offset_row: int = 0) -> int:
        """
        add a table to active sheet

        :param content: excel table object to add
        :param offset_row: give the first available row for this table object (default 0)
        :return: the next free row after the table
        """
        self.write_cells([content.header], offset_row=offset_row, offset_col=1,
                         default_format=['bg-darkblue-100', 'bold'])
        self.write_cells(content.data, offset_row=offset_row+1, offset_col=1)
        if content.autofilter and len(content.data) > 0:
            self.auto_filter(first_row=offset_row, first_col=1,
                             last_row=offset_row+len(content.data)-1, last_col=len(content.header))
        # col sizes
        for col in range(len(content.header)):
            max_len = len(content.header[col])
            for row in content.data:
                col_len = 10
                if type(row[col]) is str:
                    col_len = len(row[col])
                elif type(row[col]) is datetime.datetime:
                    col_len = len('yyyy-mm-dd hh:mm:ss.000')
                elif type(row[col]) is datetime.timedelta:
                    col_len = len('hh:mm:ss')
                max_len = max(max_len,  col_len)
            self.set_col_width(col + 1, col + 1, max_len * 1.25)
        return offset_row + len(content.data)

    def _add_excel_chart(self, content: 'ExcelChart', offset_row: int = 0) -> int:
        """
        add a chart to active sheet

        :param content: excel chart object to add
        :param offset_row: give the first available row for this table object (default 0)
        :return: the next free row after the table
        """
        sheet = self._get_sheet(self.current_sheet_name)
        if content.values and type(content.values[0]) is not List:
            content.values = [[c] for c in content.values]
        self.write_cells([[c] for c in content.categories], offset_row=offset_row, offset_col=1)
        self.write_cells(content.values, offset_row=offset_row, offset_col=2)
        # for i in range(len(content.values)):
        #     sheet.set_row(offset_row+i, options={'hidden': True})
        chart = self.workbook.add_chart({'type': content.type})
        chart.set_title({'name': content.title})
        chart.set_legend({'none': True})
        chart.add_series({
            'categories': [self.current_sheet_name, offset_row, 1, offset_row+len(content.values), 1],
            'values':     [self.current_sheet_name, offset_row, 2, offset_row+len(content.values), 2]
        })
        sheet.insert_chart(offset_row, 1, chart)
        offset_row += len(content.values)
        return offset_row

    def _add_sheet_header(self, content: 'SheetHeader', offset_row: int = 0) -> int:
        """
        add a sheet header to active sheet

        :param content: sheet header object to add
        :param offset_row: give the first available row for this header object (default 0)
        :return: the next free row after the sheet header
        """
        self.write(offset_row, 1, content.title, default_format=['title'])
        self._get_sheet(self.current_sheet_name).set_row(2 + offset_row, 5 * 15)
        self.merge_write(2 + offset_row, 1, 2+offset_row, 5, content.description, default_format=['description'])
        return 3 + offset_row

    def add_sheet(self, sheet_name: str, content: List[Union['ExcelTable', 'SheetHeader']]):
        self.current_sheet_name = sheet_name
        offset_row = 1
        for entry in content:
            if type(entry) is SheetHeader:
                offset_row = self._add_sheet_header(entry, offset_row=offset_row) + 1
            elif type(entry) is ExcelTable:
                offset_row = self._add_excel_table(entry, offset_row=offset_row) + 1
            elif type(entry) is ExcelChart:
                offset_row = self._add_excel_chart(entry, offset_row=offset_row) + 1


    def close(self):
        self.workbook.close()


class SheetHeader:
    def __init__(self):
        self.title = ''
        self.description = ''


class ExcelTable:
    def __init__(self):
        self.autofilter = False
        self.header: List = []
        self.data: List[List] = []


class ExcelChart:
    def __init__(self):
        self.values: List = []
        self.categories: List = []
        self.type = ''
        self.title = ''

