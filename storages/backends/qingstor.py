# -*- coding:utf-8 -*-
from __future__ import absolute_import, unicode_literals

import os
import posixpath
from datetime import datetime

import six
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, SuspiciousOperation
from django.core.files.base import File
from django.core.files.storage import Storage
from django.utils.encoding import filepath_to_uri, force_bytes, force_text
from six.moves.urllib_parse import urljoin

try:
    from qingstor.sdk.config import Config
    from qingstor.sdk.service.qingstor import QingStor
except ImportError:
    raise ImproperlyConfigured(
        "Could not load qingstor. "
        "See https://github.com/yunify/qingstor-sdk-python")


class QingStorFile(File):
    def __init__(self, name, storage, mode):
        self._storage = storage
        self._name = name
        self._mode = mode
        self.file = six.BytesIO()
        self._is_dirty = False
        self._is_read = False

    @property
    def size(self):
        if self._is_dirty or self._is_read:
            old_file_position = self.file.tell()
            self.file.seek(0, os.SEEK_END)
            self._size = self.file.tell()
            self.file.seek(old_file_position, os.SEEK_SET)
        if not hasattr(self, '_size'):
            self._size = self._storage.size(self._name)
        return self._size

    def read(self, num_bytes=None):
        if not self._is_read:
            content = self._storage._read(self._name)
            self.file = six.BytesIO(content)
            self._is_read = True

        if num_bytes is None:
            data = self.file.read()
        else:
            data = self.file.read(num_bytes)
        if 'b' in self._mode:
            return data
        else:
            return force_text(data)

    def write(self, content):
        if 'w' not in self._mode:
            raise AttributeError("File was opened for read-only access.")

        self.file.write(force_bytes(content))
        self._is_dirty = True
        self._is_read = True

    def close(self):
        if self._is_dirty:
            self.file.seek(0)
            self._storage._save(self._name, self.file)
        self.file.close()


def get_qingstor_config(name, default=None):
    config = os.environ.get(name, getattr(settings, name, default))
    if config is not None:
        if isinstance(config, six.string_types):
            return config.strip()
        else:
            return config
    else:
        raise ImproperlyConfigured(
            "Can't find config for '%s' either in environment"
            "variable or in setting.py" % name)


QINGSTOR_ACCESS_KEY_ID = get_qingstor_config('QINGSTOR_ACCESS_KEY_ID')
QINGSTOR_SECRET_ACCESS_KEY = get_qingstor_config('QINGSTOR_SECRET_ACCESS_KEY')
QINGSTOR_BUCKET_NAME = get_qingstor_config('QINGSTOR_BUCKET_NAME')
QINGSTOR_BUCKET_ZONE = get_qingstor_config('QINGSTOR_BUCKET_ZONE')
QINGSTOR_SECURE_URL = get_qingstor_config('QINGSTOR_SECURE_URL', 'True')


class QingStorStorage(Storage):

    location = ""

    def __init__(self,
                 access_key_id=QINGSTOR_ACCESS_KEY_ID,
                 secret_access_key=QINGSTOR_SECRET_ACCESS_KEY,
                 bucket_name=QINGSTOR_BUCKET_NAME,
                 bucket_zone=QINGSTOR_BUCKET_ZONE,
                 secure_url=QINGSTOR_SECURE_URL):
        self.config = Config(access_key_id=access_key_id, secret_access_key=secret_access_key)
        self.bucket_name = bucket_name
        self.zone = bucket_zone
        self.bucket = self._init_bucket(bucket_name, bucket_zone)
        self.secure_url = secure_url

    def _init_bucket(self, bucket_name, bucket_zone):
        qingstor = QingStor(self.config)
        bucket = qingstor.Bucket(bucket_name, bucket_zone)

        list_bucket_output = qingstor.list_buckets()

        bucket_names = []
        try:
            for bucket_exist in list_bucket_output['buckets']:
                bucket_names.append(bucket_exist['name'])
            if bucket_name not in bucket_names:
                bucket.put()
        except:
            return bucket
        return bucket

    def _clean_name(self, name):
        clean_name = posixpath.normpath(name).replace('\\', '/')

        if name.endswith('/') and not clean_name.endswith('/'):
            return clean_name + '/'
        else:
            return clean_name

    def _normalize_name(self, name):
        base_path = force_text(self.location)
        base_path = base_path.rstrip('/')

        final_path = urljoin(
            base_path.rstrip('/') + "/", name)

        base_path_len = len(base_path)
        if (not final_path.startswith(base_path) or
                final_path[base_path_len:base_path_len + 1]
                not in ('', '/')):
            raise SuspiciousOperation("Attempted access to '%s' denied." %
                                      name)
        return final_path.lstrip('/')

    def _open(self, name, mode='rb'):
        return QingStorFile(self, name=name, mode=mode)

    def _put_file(self, name, content):
        self.bucket.put_object(name, body=content)

    def _save(self, name, content):
        cleaned_name = self._clean_name(name)
        name = self._normalize_name(cleaned_name)

        self._put_file(name, content)
        return cleaned_name

    def _read(self, name):
        return self.bucket.get_object(name).content

    def delete(self, name):
        name = self._normalize_name(self._clean_name(name))
        if six.PY2:
            name = name.encode('utf-8')
        self.bucket.delete_object(name)

    def _file_stat(self, name):
        name = self._normalize_name(self._clean_name(name))
        if six.PY2:
            name = name.encode('utf-8')
        output = self.bucket.head_object(name)

        return output.headers, output.status_code

    def exists(self, name):
        headers, status_code = self._file_stat(name)
        if status_code == 200:
            return True
        else:
            return False

    def size(self, name):
        output = self.bucket.list_objects(prefix=name)
        return int(output['keys'][0]['size'])

    def modified_time(self, name):
        headers, status_code = self._file_stat(name)
        return datetime.strptime(headers['Last-Modified'], "%a, %d %b %Y %H:%M:%S GMT")

    def listdir(self, path=""):
        path = self._normalize_name(self._clean_name(path))
        dirlist = self.bucket.list_objects(prefix=path)

        files = []
        for item in list(dirlist['keys']):
            files.append(dict(item)['key'])
        return files

    def url(self, name):
        name = self._normalize_name(self._clean_name(name))
        name = filepath_to_uri(name)
        if self.secure_url:
            protocol = 'https://'
        else:
            protocol = 'http://'
        return urljoin(protocol + self.bucket_name + '.' + self.zone + '.' + self.config.host, name)
