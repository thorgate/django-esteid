import ctypes
import sys

from django.utils.encoding import force_text, force_bytes


if sys.platform.lower() == 'darwin':
    lib_ext = 'dylib'

elif sys.platform == 'win32' or sys.platform == 'cygwin':
    lib_ext = 'dll'

else:
    lib_ext = 'so'

zip_lib = ctypes.cdll.LoadLibrary("libzip.%s" % lib_ext)


class ZipStat(ctypes.Structure):
    _fields_ = [
        ('valid', ctypes.c_uint64),
        ('name', ctypes.c_char_p),
        ('index', ctypes.c_uint64),
        ('size', ctypes.c_uint64),
        ('comp_size', ctypes.c_uint64),
        ('mtime', ctypes.c_uint64),
        ('crc', ctypes.c_uint32),
        ('comp_method', ctypes.c_uint16),
        ('encryption_method', ctypes.c_uint16),
        ('flags', ctypes.c_uint32),
    ]


class Zip(ctypes.Structure):
    _fields_ = []


class ZipFile(ctypes.Structure):
    _fields_ = []


zip_lib.zip_open.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.POINTER(ctypes.c_int)]
zip_lib.zip_open.restype = ctypes.POINTER(Zip)

zip_lib.zip_close.argtypes = [ctypes.POINTER(Zip)]
zip_lib.zip_close.restype = ctypes.c_int

zip_lib.zip_get_num_entries.argtypes = [ctypes.POINTER(Zip), ctypes.c_uint32]
zip_lib.zip_get_num_entries.restype = ctypes.c_uint64

zip_lib.zip_stat_init.argtypes = [ctypes.POINTER(ZipStat)]
zip_lib.zip_stat_init.restype = None

zip_lib.zip_stat_index.argtypes = [ctypes.POINTER(Zip), ctypes.c_uint64, ctypes.c_uint32, ctypes.POINTER(ZipStat)]
zip_lib.zip_stat_index.restype = ctypes.c_int

zip_lib.zip_set_archive_comment.argtypes = [ctypes.POINTER(Zip), ctypes.c_char_p, ctypes.c_uint16]
zip_lib.zip_set_archive_comment.restype = ctypes.c_int

zip_lib.zip_delete.argtypes = [ctypes.POINTER(Zip), ctypes.c_uint64]
zip_lib.zip_delete.restype = ctypes.c_int

zip_lib.zip_source_buffer.argtypes = [ctypes.POINTER(Zip), ctypes.c_void_p, ctypes.c_uint64, ctypes.c_int]
zip_lib.zip_source_buffer.restype = ctypes.c_void_p

ZIP_OLD = False
try:
    zip_lib.zip_file_add.argtypes = [ctypes.POINTER(Zip), ctypes.c_char_p, ctypes.c_void_p, ctypes.c_uint32]
    zip_lib.zip_file_add.restype = ctypes.c_uint64

except (AttributeError, TypeError):
    ZIP_OLD = True

    zip_lib.zip_add.argtypes = [ctypes.POINTER(Zip), ctypes.c_char_p, ctypes.c_void_p]
    zip_lib.zip_add.restype = ctypes.c_uint64

zip_lib.zip_source_free.argtypes = [ctypes.c_void_p]
zip_lib.zip_source_free.restype = None

zip_lib.zip_fopen_index.argtypes = [ctypes.POINTER(Zip), ctypes.c_uint64, ctypes.c_uint32]
zip_lib.zip_fopen_index.restype = ctypes.POINTER(ZipFile)

zip_lib.zip_fread.argtypes = [ctypes.POINTER(ZipFile), ctypes.c_void_p, ctypes.c_uint64]
zip_lib.zip_fread.restype = ctypes.c_uint64

zip_lib.zip_fclose.argtypes = [ctypes.POINTER(ZipFile)]
zip_lib.zip_fclose.restype = ctypes.c_int


class ZIP:
    READ = 0
    CREATE = 1
    EXCL = 2
    CHECKCONS = 4
    TRUNCATE = 8

    ERR_OK = 0


class OpenMode:
    NOT_OPEN = None

    READ_ONLY = ZIP.READ
    WRITE = ZIP.CREATE
    NEW = ZIP.CREATE | ZIP.TRUNCATE


class ZipEntry(object):
    def __init__(self, the_archive, name, index, size, comp_method, comp_size, crc, mtime):
        self.archive = the_archive
        self.name = name
        self.index = index
        self.size = size
        self.comp_method = comp_method
        self.comp_size = comp_size
        self.crc = crc
        self.mtime = mtime

    def read(self):
        return self.archive.read_entry(self)

    def is_file(self):
        return self.name and self.name[-1] != '/'

    def is_directory(self):
        return not self.is_file()


class CustomZipArchive(object):
    def __init__(self, file_name, open_mode=None):
        self.file_name = file_name

        self.__handle = None
        self.mode = OpenMode.NOT_OPEN

        if open_mode is not None:
            self.open(open_mode)

    def open(self, mode):
        assert mode in [OpenMode.READ_ONLY, OpenMode.WRITE, OpenMode.NEW]

        error_flag = ctypes.c_int(0)

        self.__handle = zip_lib.zip_open(force_bytes(self.file_name), mode, ctypes.byref(error_flag))

        if error_flag.value != ZIP.ERR_OK:
            raise Exception('Failed to open zip file with error %d' % error_flag.value)

        elif not self.__handle:
            raise Exception('Failed to obtain zip file handle. Unknown error')

        else:
            self.mode = mode

            return True

    def close(self):
        assert self.__handle

        result = zip_lib.zip_close(self.__handle)

        self.__handle = None
        self.mode = OpenMode.NOT_OPEN

        return result

    def get_handle(self):
        return self.__handle

    def is_open(self):
        return self.mode != OpenMode.NOT_OPEN

    def get_num_entries(self):
        assert self.is_open()

        return self.__handle and zip_lib.zip_get_num_entries(self.__handle, 0)

    def get_entries(self):
        assert self.is_open()

        stat = ZipStat()
        zip_lib.zip_stat_init(stat)
        entries = []

        for i in range(0, self.get_num_entries()):
            result = zip_lib.zip_stat_index(self.__handle, i, 0, stat)

            if result == 0:
                entries.append(self.create_entry(stat))

            else:
                pass  # Handle error?

        return entries

    def create_entry(self, stat):
        return ZipEntry(self, force_text(stat.name), stat.index, stat.size,
                        stat.comp_method, stat.comp_size, stat.crc, stat.mtime)

    def set_comment(self, comment):
        assert self.is_open()

        return zip_lib.zip_set_archive_comment(self.__handle, force_bytes(comment), ctypes.sizeof(ctypes.c_char) * len(comment)) == 0

    def delete_entry(self, file_entry):
        assert file_entry.archive == self
        assert self.is_open()
        assert self.mode != OpenMode.READ_ONLY

        if file_entry.is_file():
            return zip_lib.zip_delete(self.__handle, file_entry.index) == 0

        else:
            raise NotImplementedError('Cannot delete directories')

    def add_entry(self, filename, data):
        assert self.is_open()

        # NOTE: Cannot create directories
        filename = force_bytes(filename)
        data = force_bytes(data)

        source = zip_lib.zip_source_buffer(self.__handle, data, ctypes.sizeof(ctypes.c_char) * len(data), 0)
        if source != 0:
            if ZIP_OLD:
                res = zip_lib.zip_add(self.__handle, filename, source)
            else:
                res = zip_lib.zip_file_add(self.__handle, filename, source, 0)

            if res >= 0:
                return True

            else:
                zip_lib.zip_source_free(source)

        return False

    def read_entry(self, file_entry):
        assert file_entry.archive == self
        assert self.is_open()
        assert file_entry.is_file()

        zip_file = zip_lib.zip_fopen_index(self.__handle, file_entry.index, 0)

        if zip_file:
            buf = ctypes.create_string_buffer(b'', file_entry.size)

            result = zip_lib.zip_fread(zip_file, ctypes.byref(buf), file_entry.size)

            zip_lib.zip_fclose(zip_file)

            assert result == file_entry.size

            return buf.raw

        return None
