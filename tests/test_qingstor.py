# -*- coding:utf-8 -*-
from __future__ import absolute_import, print_function, unicode_literals

import logging
import os
import unittest
import uuid
from datetime import datetime
from os.path import join

import pytest
import six

from storages.backends.qingstor import QingStorFile, QingStorStorage

try:
    from unittest import mock
except ImportError:
    import mock

LOGGING_FORMAT = '\n%(levelname)s %(asctime)s %(message)s'
logging.basicConfig(level=logging.INFO, format=LOGGING_FORMAT)
logger = logging.getLogger(__name__)

USING_TRAVIS = os.environ.get('USING_TRAVIS', None) is None

UNIQUE_PATH = str(uuid.uuid4())


class QingStorageTest(unittest.TestCase):
    def setUp(self):
        self.storage = QingStorStorage()

    def test_file_init(self):
        qingstor_file = QingStorFile('foo', self.storage, mode='rb')
        assert qingstor_file._mode == 'rb'
        assert qingstor_file._name == 'foo'

    def test_write_to_read_only_file(self):
        with pytest.raises(AttributeError):
            qingstor_file = QingStorFile('foo', self.storage, mode='rb')
            qingstor_file.write('fail')

    def test_write_and_delete_file(self):
        ASSET_FILE_NAMES = ['Write&Delete.txt', '写和删.txt']
        for assert_file_name in ASSET_FILE_NAMES:
            REMOTE_PATH = join(UNIQUE_PATH, assert_file_name)

            qingstor_file = QingStorFile(REMOTE_PATH, self.storage, mode='wrb')

            content = 'Hello,QingStor!'

            dummy_file = six.BytesIO()
            dummy_file.write(content)
            dummy_file.seek(0, os.SEEK_END)
            file_size = dummy_file.tell()

            qingstor_file.write(content)

            self.storage.size = mock.Mock(file_size)
            assert qingstor_file.size == file_size

            qingstor_file.read = mock.Mock(return_value=content)
            assert qingstor_file.read() == content

            now = datetime.utcnow()

            self.storage.modified_time = mock.Mock(return_value=now)
            modified_time = self.storage.modified_time(REMOTE_PATH)

            time_delta = max(now, modified_time) - min(now, modified_time)

            assert time_delta.seconds < 180

            self.storage.bucket.delete_object = mock.MagicMock()
            self.storage.delete(REMOTE_PATH)

            self.storage.exists = mock.Mock(return_value=False)
            assert self.storage.exists(REMOTE_PATH) is False

    def test_read_file(self):
        ASSET_FILE_NAMES = ['Read.txt', '读.txt']

        for assert_file_name in ASSET_FILE_NAMES:
            REMOTE_PATH = join(UNIQUE_PATH, assert_file_name)

            test_file = six.BytesIO()
            test_file.write('Hello,QingStor!')
            test_file.seek(0)
            self.storage.save(REMOTE_PATH, test_file)
            test_file.close()

            qingstor_file_bin = QingStorFile(REMOTE_PATH, self.storage, mode='rb')

            assert qingstor_file_bin._is_read is False

            assert qingstor_file_bin._is_dirty is False

            qingstor_file_bin.close()

            qingstor_file = QingStorFile(REMOTE_PATH, self.storage, mode='r')

            self.storage._read = mock.Mock(return_value='Hello,QingStor!')
            content = qingstor_file.read()

            assert content.startswith('Hello')

            qingstor_file.file.close()

    def test_dirty_file(self):
        ASSET_FILE_NAME = '测试脏文件.txt'
        REMOTE_PATH = join(UNIQUE_PATH, ASSET_FILE_NAME)

        qingstor_file = QingStorFile(REMOTE_PATH, self.storage, mode='rw')

        assert qingstor_file._is_read is False
        assert qingstor_file._is_dirty is False

        self.storage.exists = mock.Mock(return_value=False)
        assert self.storage.exists(REMOTE_PATH) is False

        qingstor_file.write('Hello QingStor!')

        assert qingstor_file._is_read is True
        assert qingstor_file._is_dirty is True

        qingstor_file.close()

        self.storage.exists = mock.Mock(return_value=True)
        assert self.storage.exists(REMOTE_PATH) is True

    def test_listdir(self):
        filenames = ['file1', 'file2', 'file3', 'file4']
        filenames_join = []
        for filename in filenames:
            qingstor_file = QingStorFile(join(UNIQUE_PATH, 'foo', filename), self.storage, 'w')
            filenames_join.append(join(UNIQUE_PATH, 'foo', filename))
            qingstor_file.write('test text')
            qingstor_file.file.close()

        self.storage.listdir = mock.Mock(return_value=sorted(filenames_join))
        files = self.storage.listdir(join(UNIQUE_PATH, 'foo'))

        assert sorted(files) == sorted(filenames_join)

    def test_url(self):
        name = "test.txt"
        assert self.storage.url(name) == 'https://test.test.qingstor.com/test.txt'

    def tearDown(self):
        pass
