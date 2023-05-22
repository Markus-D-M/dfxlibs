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


import logging
import re
from typing import TYPE_CHECKING, Dict, Generator, List
from signify.authenticode import SignedPEFile, AuthenticodeVerificationResult
from io import BytesIO
import xmltodict

if TYPE_CHECKING:
    import sqlite3

from dfxlibs.general.baseclasses.defaultclass import DefaultClass
from dfxlibs.general.baseclasses.file import File
from dfxlibs.general.baseclasses.partition import Partition
from dfxlibs.windows.shortcuts.lnkfile import LnkFile
from dfxlibs.general.helpers.db_filter import db_and, db_eq, db_like, db_or
from dfxlibs.cli.environment import env

_logger = logging.getLogger(__name__)


def verify_environment_vars(db_file_cur: 'sqlite3.Cursor') -> Dict[str, str]:
    candidates = {
        '%ALLUSERSPROFILE%': '/ProgramData',
        '%ProgramData%': '/ProgramData',
        '%ProgramFiles%': '/Program Files',
        '%ProgramFiles(x86)%': '/Program Files (x86)',
        '%SystemRoot%': '/Windows',
        '%windir%': '/Windows'
    }
    # check if dirs exists and return if yes
    result = {}
    for candidate in candidates:
        res = File.db_select_one(db_file_cur, db_filter=db_like('parent_folder', candidates[candidate]))
        if res:
            result[candidate] = candidates[candidate]
    return result


def _dn2cn(dn: str) -> str:
    parts = dn.split(',')
    for part in parts:
        part = part.strip()
        if part.lower().startswith('cn='):
            return part[3:].strip()
    return dn


def _startup_folders(db_file_cur: 'sqlite3.Cursor', partition: Partition, autoruns=None):
    if autoruns is None:
        autoruns = list()
    startup_files: Generator['File'] = File.db_select(db_file_cur,
                                                      db_filter=db_and(
                                                          db_or(
                                                              db_like('parent_folder',
                                                                      '/Users/%/AppData/Roaming/Microsoft/Windows/'
                                                                      'Start Menu/Programs/Startup'),
                                                              db_like('parent_folder',
                                                                      '/Documents and Settings/%/Start Menu/Programs/'
                                                                      'Startup'),
                                                              db_like('parent_folder',
                                                                      '/Dokumente und Einstellungen/%/Startmenü/'
                                                                      'Programme/Autostart')
                                                          ),
                                                          db_eq('is_dir', 0),
                                                          db_eq('source', 'filesystem'),
                                                          db_eq('allocated', 1)))
    for startup_file in startup_files:
        if startup_file.name.lower() == 'desktop.ini':
            continue
        _, _, user_id, _ = startup_file.full_name.split('/', maxsplit=3)
        if startup_file.extension.lower() == 'lnk':
            # Link File
            startup_file.open(partition)
            lnk_file = LnkFile(startup_file)
            ar = Autorun(description=lnk_file.description if lnk_file.description else lnk_file.lnk_filename,
                         commandline=lnk_file.command_line,
                         source=startup_file.full_name,
                         ar_type='Startup Folder',
                         user=user_id)
            autoruns.append(ar)
        else:
            ar = Autorun(description=startup_file.name,
                         commandline=startup_file.full_name,
                         source=startup_file.full_name,
                         ar_type='Startup Folder',
                         user=user_id)
            autoruns.append(ar)
    return autoruns


def _scheduled_tasks(db_file_cur: 'sqlite3.Cursor', partition: Partition, autoruns=None):
    if autoruns is None:
        autoruns = list()
    task_files: Generator['File'] = File.db_select(db_file_cur, db_filter=db_and(db_like('parent_folder',
                                                                                         '/Windows/System32/Tasks%'),
                                                                                 db_eq('is_dir', 0),
                                                                                 db_eq('source', 'filesystem'),
                                                                                 db_eq('allocated', 1)))
    for task_file in task_files:
        task_file.open(partition)
        task = xmltodict.parse(task_file.read())
        try:
            if task['Task']['Settings']['Enabled'].lower() != 'true':
                continue
        except KeyError:
            continue
        context = {}
        try:
            context[task['Task']['Principals']['Principal']['@id']] = task['Task']['Principals']['Principal']['UserId']
        except KeyError:
            pass
        try:
            command = task['Task']['Actions']['Exec']['Command']
            if '@Context' in task['Task']['Actions'] and task['Task']['Actions']['@Context'] in context:
                user_id = context[task['Task']['Actions']['@Context']]
            else:
                user_id = ''
        except KeyError:
            continue
        params = ' ' + task['Task']['Actions']['Exec']['Arguments'] \
            if 'Arguments' in task['Task']['Actions']['Exec'] and task['Task']['Actions']['Exec']['Arguments'] else ''
        ar = Autorun(description=task_file.name,
                     commandline=command + params,
                     source=task_file.full_name,
                     ar_type='Scheduled Task',
                     user=user_id)
        autoruns.append(ar)
    return autoruns


def get_autoruns(db_file_cur: 'sqlite3.Cursor', partition: Partition):
    autoruns: List[Autorun] = env['globals']['software'].get_autoruns()
    autoruns = env['globals']['system'].get_autoruns(autoruns)
    autoruns = env['globals']['user'].get_autoruns(autoruns)
    autoruns = _scheduled_tasks(db_file_cur, partition, autoruns)
    autoruns = _startup_folders(db_file_cur, partition, autoruns)
    env_vars = verify_environment_vars(db_file_cur)
    result = []
    for ar in autoruns:
        p_dir = ar.parent_dir.replace('\\', '/')
        if p_dir[1:3] == ':/':
            p_dir = p_dir[2:]
        for env_var in env_vars:
            p_dir = re.sub(env_var, env_vars[env_var], p_dir, flags=re.I)

        exe_files: Generator['File'] = File.db_select(db_file_cur, db_filter=db_and(db_like('parent_folder', p_dir),
                                                                                    db_like('name', ar.exe_name),
                                                                                    db_eq('source', 'filesystem'),
                                                                                    db_eq('allocated', 1)))
        exe_list = [e for e in exe_files]
        if len(exe_list) == 0:
            # file not found
            ar.add_info = 'Binary not found'
        elif len(exe_list) > 1:
            # multiple candidates found
            pass
        else:
            ar.created = exe_list[0].fn_crtime \
                if exe_list[0].fn_crtime and exe_list[0].fn_crtime != exe_list[0].crtime \
                else exe_list[0].fn_crtime
            exe_list[0].open(partition)
            # BytesIO Workaround - SignedPEFile doesn't like my filelike object (always hash missmatch)
            fdata = BytesIO(exe_list[0].read())
            pefile = SignedPEFile(fdata)
            status, msg = pefile.explain_verify()
            if status == AuthenticodeVerificationResult.NOT_SIGNED:
                ar.signature = 'not signed'
            elif status == AuthenticodeVerificationResult.OK:
                ar.signature = 'signed'
                for signed_data in pefile.signed_datas:
                    certs = {cert.serial_number: cert for cert in signed_data.certificates}
                    ar.signer += ('\n' if ar.signer else '') + \
                        _dn2cn(certs[signed_data.signer_info.serial_number].subject.dn)
                    if signed_data.signer_info.countersigner:
                        if hasattr(signed_data.signer_info.countersigner, 'certificates'):
                            certs.update({cert.serial_number: cert
                                          for cert in signed_data.signer_info.countersigner.certificates})
                        try:
                            ar.countersigner += ('\n' if ar.countersigner else '') + \
                                _dn2cn(certs[signed_data.signer_info.countersigner.serial_number].subject.dn)
                        except AttributeError:
                            ar.countersigner += ('\n' if ar.countersigner else '') + \
                                _dn2cn(
                                    certs[signed_data.signer_info.countersigner.signer_info.serial_number].subject.dn)
                        ar.signing_timestamp += ('\n' if ar.signing_timestamp else '') + \
                            signed_data.signer_info.countersigner.signing_time.isoformat()
            else:
                ar.signature = 'error: ' + str(msg)

        result.append(ar)
    return result


class Autorun(DefaultClass):
    table_header = ['Description', 'Executable', 'Directory', 'Commandline',
                    'Type', 'Additional Info', 'User', 'Executable Created',
                    'Signature', 'Signer', 'Countersigner', 'Signing Timestamp',
                    'Source']

    def to_list(self):
        return [self.description, self.exe_name, self.parent_dir, self.commandline,
                self.type, self.add_info, self.user, self.created,
                self.signature, self.signer, self.countersigner, self.signing_timestamp,
                self.source]

    def __init__(self, description: str = '', commandline: str = '', source: str = '', ar_type: str = '',
                 user: str = ''):
        self.commandline = ''  # full commandline
        self.source = source
        self.parent_dir = ''  # parent from relevant binary
        self.exe_name = ''  # relevant binary (e.g. the dll file, when using rundll32)
        self.parameters = ''  # parameters for relevant binary
        self.add_info = ''
        self.type = ar_type  # Type of autorun (e.g. registry runkey)
        self.user = user  # owning user
        self.description = description  # autorun name (e.g. reg value name, link name, service name)
        self.created = ''  # binary create date
        self.signature = ''  # signature infos for relevant binary
        self.signer = ''
        self.countersigner = ''
        self.signing_timestamp = ''
        if commandline:
            self.add_commandline(commandline)

    @staticmethod
    def _tokenize_commandline(commandline: str) -> List[str]:
        # tokenize and look for quotation marks
        in_parenthesis = False
        escape_next = False
        cur_token = ''
        token = []
        for char in commandline:
            if escape_next:
                cur_token += char
                escape_next = False
            elif char in ["'", '"']:
                if in_parenthesis:
                    if cur_token:
                        token.append(cur_token)
                        cur_token = ''
                in_parenthesis = not in_parenthesis
            elif in_parenthesis:
                cur_token += char
            elif char == " ":
                if cur_token:
                    token.append(cur_token)
                cur_token = ''
            else:
                cur_token += char
        if cur_token:
            token.append(cur_token)

        # check if first tokens should be merged (e.g. space in folder) - this method only merge one space per subfolder
        # which is sufficent for most cases
        if len(token) > 0 and " " not in token[0]:
            # if there is a space in token[0] there is no need for merging (tokenization via parenthesis)
            while len(token) > 1:
                if len(token[0]) > 4 and (token[0][-3] == '.' or token[0][-4] == '.'):
                    # only merge token, if token 0 don'T look like a filename
                    break
                if " " in token[1]:
                    # only merge token, if there is no space in them (spaces only occurs while using parenthesis for
                    # tokenization)
                    break
                if "\\" in token[0][1:-1] and '\\' in token[1][1:-1] and \
                        not any([char in token[1] for char in '*/:<>?|']):
                    # merge if backslashes in the first two tokens not as first or last char and token[1] does
                    # not contain any forbidden chars
                    token = [token[0] + " " + token[1], *token[2:]]
                else:
                    # else merging finished
                    break

        return token

    def _split_commandline(self, commandline: str) -> (str, str, str):
        parts = self._tokenize_commandline(commandline)
        fullpath = ''
        # try to handle folder name with spaces
        while '.' not in fullpath[:-1] and len(parts) > 0:
            fullpath += (' ' + parts.pop(0))
            if fullpath.strip().lower() in ['cmd', 'cscript', 'wscript', 'powershell']:
                # break for some starter tools
                break
        params = ' '.join(parts)
        fullpath = fullpath.strip(' "')

        if '\\' in fullpath:
            path, exe = fullpath.rsplit('\\', maxsplit=1)
        else:
            path = ''
            exe = fullpath
        return path, exe, params

    def add_commandline(self, commandline: str):
        self.commandline = commandline
        path, exe, params = self._split_commandline(commandline)

        self.parent_dir = path
        self.exe_name = exe
        self.parameters = params

        rescan = True
        while rescan:
            rescan = False
            # handle rundll32.exe calls
            if 'rundll32.exe' == self.exe_name.lower() and '\\system32' in self.parent_dir.lower():
                try:
                    dll, func_params = self.parameters.split(',', maxsplit=1)
                    if '\\' in dll:
                        path, exe = dll.rsplit('\\', maxsplit=1)
                    else:
                        path = ''
                        exe = dll
                    self.parent_dir = path
                    self.exe_name = exe
                    self.parameters = func_params
                    rescan = True
                except ValueError:
                    pass

            # handle cmd.exe calls
            if self.exe_name.lower() in ['cmd.exe', 'cmd'] and self.parameters.lower().strip().startswith('/c '):
                try:
                    _, commandline2 = self.parameters.split(' ', maxsplit=1)  # strip '/c'
                    path2, exe2, params2 = self._split_commandline(commandline2)
                    self.parent_dir = path2
                    self.exe_name = exe2
                    self.parameters = params2
                    rescan = True
                except ValueError:
                    pass

            # handle wscript/cscript calls
            if self.exe_name.lower() in ['cscript.exe', 'cscript', 'wscript.exe', 'wscript']:
                try:
                    path2, exe2, params2 = self._split_commandline(self.parameters)
                    self.parent_dir = path2
                    self.exe_name = exe2
                    self.parameters = params2
                    rescan = True
                except ValueError:
                    pass

            # handle powershell calls
            if self.exe_name.lower() in ['powershell.exe'] and '.ps1' in self.parameters.lower():
                try:
                    parts = self._tokenize_commandline(self.parameters)
                    while len(parts) > 0:
                        if '.ps1' not in parts[0].lower():
                            parts.pop(0)
                        else:
                            break
                    if len(parts) > 0:
                        path2, exe2, params2 = self._split_commandline(' '.join(parts))
                        self.parent_dir = path2
                        self.exe_name = exe2
                        self.parameters = params2
                        rescan = True
                except ValueError:
                    pass
