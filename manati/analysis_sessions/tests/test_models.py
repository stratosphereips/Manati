from test_plus.test import TestCase
from manati.analysis_sessions.models import AnalysisSession
from bat import bro_log_reader
import csv
import uuid
import os


class TestAnalysisSession(TestCase):

    def setUp(self):
        self.user = self.make_user()
        self.path_dir_files = str(os.path.join(os.path.dirname(__file__), 'files'))

    def test__str__(self):
        self.assertEqual(self.user.__str__(),
            'testuser'  # This is the default username for self.make_user()
        )

    @staticmethod
    def __prepare_header__(key_list):
        header =[]
        for index, key in enumerate(key_list):
            header.append({'visible': True,'order': index, 'column_name': key})
        header_length = len(header)
        for column_name in ['verdict', 'register_status', 'dt_id','uuid']:
            header.append({'visible': True,'order': header_length, 'column_name': column_name})
            header_length += 1
        return header

    def __assert_for_creation_analysis_session__(self,filename, key_list, weblogs, current_user, type_file, uuid_str, num_lines):
        header = TestAnalysisSession.__prepare_header__(key_list)
        self.assertIsNotNone(filename)
        self.assertIsNotNone(header)
        self.assertIsNotNone(weblogs)
        self.assertIsNotNone(current_user)
        self.assertIsNotNone(type_file)
        self.assertIsNotNone(uuid_str)
        analysis_session = AnalysisSession.objects.create(filename, header, weblogs, current_user, type_file, uuid_str)
        self.assertIsNotNone(analysis_session)
        self.assertEqual(analysis_session.type_file, type_file)
        self.assertEqual(analysis_session.weblog_set.count(), num_lines - 1)

    def test_cisco_files(self):
        filename = 'weblogs_example.csv'
        weblogs = []
        key_list = None
        current_user = self.user
        type_file = AnalysisSession.TYPE_FILES.cisco_file
        uuid_str = str(uuid.uuid4())
        num_lines = 1
        rows = []
        path_filename = str(os.path.join(self.path_dir_files, filename))

        with open(path_filename) as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                if not key_list:
                    key_list = row.keys()
                value = row.values()
                value.append('undefined')
                value.append(1)
                value.append(str(num_lines))
                value.append(uuid_str)
                weblogs.append(value)
                rows.append(row)
                num_lines += 1

        self.__assert_for_creation_analysis_session__(filename, key_list, weblogs,
                                                   current_user, type_file, uuid_str, num_lines)

    def test_bro_files(self):
        filename = 'http.log'
        weblogs = []
        key_list = None
        current_user = self.user
        type_file = AnalysisSession.TYPE_FILES.bro_http_log
        uuid_str = str(uuid.uuid4())
        num_lines = 1
        rows = []
        path_filename = str(os.path.join(self.path_dir_files, filename))
        reader = bro_log_reader.BroLogReader(path_filename)
        for row in reader.readrows():
            if not key_list:
                key_list = row.keys()
            row['ts'] = str(row['ts'])
            value = row.values()
            value.append('undefined')
            value.append(1)
            value.append(str(num_lines))
            value.append(uuid_str)
            weblogs.append(value)
            rows.append(row)
            num_lines += 1

        self.__assert_for_creation_analysis_session__(filename, key_list, weblogs,
                                                   current_user, type_file, uuid_str, num_lines)
