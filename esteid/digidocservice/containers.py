import base64
import hashlib
import io
import re
import sys
import tempfile
from lxml import etree

from django.utils.encoding import force_bytes, force_text

from .czip import CustomZipArchive, OpenMode


class BDOCException(Exception):
    pass


class HashCodesFileEntry(object):
    def __init__(self, filename, content, size):
        self.filename = filename
        self.content = content
        self.size = size

    def as_xml(self):
        root = etree.Element('file-entry')

        root.attrib['full-path'] = self.filename
        root.attrib['hash'] = self.content
        root.attrib['size'] = str(self.size)

        return root


class HashCodesXml(object):
    def __init__(self, algorithm):
        self.algorithm = algorithm
        self.file_entries = []

    def from_data_files(self, data_files):
        self.file_entries = []

        for data_file in data_files:
            self.file_entries.append(self.convert_data_file_to_file_entry(data_file))

        return self.write()

    def convert_data_file_to_file_entry(self, data_file):
        return HashCodesFileEntry(data_file.filename, self.file_hash(data_file.content), data_file.size)

    def file_hash(self, content):
        return base64.b64encode(getattr(hashlib, self.algorithm)(content).digest())

    def write(self):
        root = etree.Element('hashcodes')

        for file_entry in self.file_entries:
            root.append(file_entry.as_xml())

        return "%s%s" % ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>', force_text(etree.tostring(root)))


class ZipDataFile(object):
    def __init__(self, filename, content, size):
        self.filename = filename
        self.content = force_bytes(content, errors='surrogateescape')
        self.size = size

    def __str__(self):
        return 'ZipDataFile(filename=%s, size=%s, content[:8]=%s)' % (self.filename, self.size, self.content[:8])


class BdocContainer(object):
    DEFAULT_HASH_ALGORITHM = 'sha256'
    HASH_CODES_FILES_REGEX = r'^META-INF/hashcodes-\w+.xml$'

    HASH_ALGORITHMS = ['sha256', 'sha512']

    @classmethod
    def hash_code(cls, content):
        return base64.b64encode(hashlib.sha256(content).digest())

    def __init__(self, file_data, data_files=None):
        if isinstance(file_data, io.BytesIO):
            raw_data = file_data.getvalue()

        else:
            raw_data = file_data

        if data_files is None:
            data_files = []

        self.file_data = raw_data
        self.data_files = data_files
        self.temp_dir = tempfile.TemporaryDirectory()

    def __enter__(self):
        return self

    def __exit__(self, *args, **kwargs):
        self.temp_dir.cleanup()

    def get_temporary_file(self):
        the_file = tempfile.NamedTemporaryFile(dir=self.temp_dir.name, suffix='.zip', delete=False)

        with open(the_file.name, 'wb') as f:
            f.write(self.file_data)

        return the_file.name

    def hash_codes_format(self):
        zip_file = self.get_temporary_file()
        archive = CustomZipArchive(zip_file)

        if archive.open(OpenMode.WRITE):
            # Load entries
            entries = archive.get_entries()

            # Remove data files
            data_files = self.delete_data_files(archive, entries)

            # Write hashcode files
            self.write_hash_code_files(archive, data_files)

            # Set comment
            archive.set_comment(self.__get_container_comment())

            # Commit changes
            archive.close()

            with open(zip_file, 'rb') as handle:
                return handle.read()

        else:
            raise BDOCException('ZipArchive could not be opened')

    def data_files_format(self):
        zip_file = self.get_temporary_file()
        archive = CustomZipArchive(zip_file)

        if archive.open(OpenMode.WRITE):
            # Load entries
            entries = archive.get_entries()

            # Remove hashcode files
            self.delete_hashcode_files(archive, entries)

            # Write datafiles
            for datafile in self.data_files:
                archive.add_entry(datafile.file_name, datafile.content)

            # Commit changes
            archive.close()

            # Return result
            with open(zip_file, 'rb') as handle:
                file_data = handle.read()

            return file_data

        else:
            raise BDOCException('ZipArchive could not be opened')

    def delete_data_files(self, archive, entries=None):
        return self.__delete_files(archive, entries, lambda filename: self.__is_data_file(filename))

    def delete_hashcode_files(self, archive, entries=None):
        return self.__delete_files(archive, entries, lambda filename: self.__is_hash_code_file(filename))

    def write_hash_code_files(self, archive, data_files):
        for algorithm in self.HASH_ALGORITHMS:
            filename = "META-INF/hashcodes-%s.xml" % algorithm
            file_data = HashCodesXml(algorithm).from_data_files(data_files)

            archive.add_entry(filename, file_data)

    @staticmethod
    def __delete_files(archive, entries, test_func):
        deleted_files = []

        if entries is None:
            entries = archive.get_entries()

        for file_entry in entries:
            filename = file_entry.name

            if test_func(filename):
                deleted_files.append(ZipDataFile(file_entry.name, file_entry.read(), file_entry.size))

                # Remove the entry from archive
                archive.delete_entry(file_entry)

        return deleted_files

    @classmethod
    def __is_hash_code_file(cls, file_name):
        return re.match(cls.HASH_CODES_FILES_REGEX, file_name)

    @classmethod
    def __is_data_file(cls, file_name):
        return file_name != 'mimetype' and file_name[:9] != 'META-INF/'

    @classmethod
    def __get_container_comment(cls):
        return 'digidoc %s - python %s, %s' % ('0.0.1', sys.version_info, sys.platform)
