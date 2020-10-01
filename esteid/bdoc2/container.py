import io
import os
import re
from zipfile import ZipFile, ZIP_DEFLATED, ZIP_STORED

from lxml import etree

from .exceptions import BDoc2Error
from .xmlsig import XmlSignature


class BDoc2FileError(BDoc2Error):
    pass


class BDoc2File(object):
    """
    Manipulate BDoc v2 containers.

    Create a new container:

        bdoc = BDoc2File()
        bdoc\
            .add_file('test.pdf', b'Test data', 'application/pdf')\
            .add_signature(xmlsig)\
            .save('test.bdoc')

    Use `name` to open an existing container:

        bdoc = BDoc2File('test.bdoc')
        bdoc.verify_signatures()
        with bdoc.open_file('test.pdf') as f:
            assert f.read() == b'Test data'

        another_xmlsig = XmlSignature.create()...
        bdoc.add_signature(another_xmlsig).save()

    Spec: https://www.id.ee/public/bdoc-spec212-eng.pdf [1]
    """
    META_DIR = 'META-INF'
    # > The names of these files shall contain the string "signatures" [1], ch.8
    SIGNATURE_FILES_REGEX = r'^%s/signatures(\d+)\.xml$' % META_DIR
    SIGNATURE_FILES_TEMPLATE = '%s/signatures{}.xml' % META_DIR

    # Manifest structure constants
    MANIFEST_FILE = 'manifest.xml'
    MANIFEST_NS = "urn:oasis:names:tc:opendocument:xmlns:manifest:1.0"
    MANIFEST_NAMESPACES = {
        'manifest': MANIFEST_NS,
    }
    MANIFEST_TAG_FILE_ENTRY = '{%s}file-entry' % MANIFEST_NS
    MANIFEST_ATTR_MEDIA_TYPE = '{%s}media-type' % MANIFEST_NS
    MANIFEST_ATTR_FULL_PATH = '{%s}full-path' % MANIFEST_NS

    MANIFEST_TEMPLATE_FILE = os.path.join(os.path.dirname(__file__), 'templates', 'manifest.xml')
    MIME_TYPE = b'application/vnd.etsi.asic-e+zip'
    MIME_TYPE_FILE = 'mimetype'

    def __init__(self, name=None):
        """
        Create or open a BDOC container file
        """
        self.name = name

        if name is None:
            buffer = io.BytesIO()
            self._zip_file = ZipFile(buffer, 'a')
            self._add_mimetype()
            self._manifest = None
            self._manifest_write_required = True
        else:
            with open(name, 'rb') as f:
                buffer = io.BytesIO(f.read())
            # create a zip file in 'append' mode, to make possible both reading and adding files
            self._zip_file = ZipFile(buffer, 'a')

            self._verify_container_contents()
            self._manifest_write_required = False

        self._zip_buffer = buffer

    def __str__(self):
        return self.name or repr(self)

    def save(self, name=None):
        """Create the actual BDoc file in FS, with current content
        """
        if name is None:
            name = self.name

        if name is None:
            raise BDoc2FileError("Can't save BDOC without a file name")

        if not self.data_file_names:
            raise BDoc2FileError("Can't save BDOC without data files")

        self._write_manifest()

        with open(name, 'wb') as f:
            f.write(self.get_contents())
        return self

    def add_file(self, file_name, binary_data, mime_type='application/octet-stream', compress=True):
        """Add a data file"""
        manifest_xml = self._get_manifest_xml()
        new_manifest_entry = etree.Element(self.MANIFEST_TAG_FILE_ENTRY)
        new_manifest_entry.attrib[self.MANIFEST_ATTR_MEDIA_TYPE] = mime_type
        new_manifest_entry.attrib[self.MANIFEST_ATTR_FULL_PATH] = file_name
        manifest_xml.append(new_manifest_entry)
        compress_type = ZIP_DEFLATED if compress else ZIP_STORED
        self._zip_file.writestr(file_name, binary_data, compress_type)
        self._manifest_write_required = True
        return self

    @property
    def data_file_names(self):
        return [name for name, _ in self._enumerate_data_files()]

    @property
    def signature_file_names(self):
        return self._enumerate_signatures()

    def get_contents(self):
        self._zip_file.close()
        value = self._zip_buffer.getvalue()
        self._zip_file = ZipFile(self._zip_buffer, 'a')
        return value

    def has_data_files(self):
        return any(self._enumerate_data_files())  # False if no elements

    def iter_data_files(self):
        """
        Iterate over 3-tuples of file name, content and mime_type
        """
        for file_name, mime_type in self._enumerate_data_files():
            with self.open_file(file_name) as f:
                yield file_name, f.read(), mime_type

    def open_file(self, file_name):
        return self._zip_file.open(file_name)

    def add_signature(self, signature):
        """Add a signature calculated over the data files.

        :param XmlSignature signature:
        """
        # I know it's bullshit but without this here, the zip container randomly gets corrupted
        # after adding a signature file, with errors like:
        # """ zipfile.BadZipFile: File name in directory 'META-INF/signatures1.xml'
        # """ and header b'META-INF/signatures2.xml' differ.
        self.verify_container()

        embedded_signatures = sorted(self._enumerate_signatures())

        if embedded_signatures:
            last_n = re.match(self.SIGNATURE_FILES_REGEX, embedded_signatures[-1]).group(1)
            next_n = int(last_n) + 1  # even with alphabetic file sorting, this gives valid next number
        else:
            next_n = 1

        new_sig_file = self.SIGNATURE_FILES_TEMPLATE.format(next_n)
        assert new_sig_file not in embedded_signatures
        self._zip_file.writestr(new_sig_file, signature.dump(), ZIP_DEFLATED)
        return self

    def iter_signatures(self):
        """Iterate over embedded signatures
        """
        for entry in self._enumerate_signatures():
            with self.open_file(entry) as f:
                yield XmlSignature(f.read())

    def verify_signatures(self):
        """Verify all signatures in the container

        :raises signature_verifier.SignatureVerificationError:
        """
        for xmlsig in self.iter_signatures():
            xmlsig.verify()
        return self

    def verify_container(self):
        failed = self._zip_file.testzip()
        if failed:
            raise BDoc2FileError('The container contains errors. First broken file: %s' % failed)
        return self

    def _write_manifest(self):
        """Create/update the manifest"""
        if not self._manifest_write_required:
            return

        manifest_xml = self._get_manifest_xml()

        if self._manifest_file_name in self._read_toc():
            self._delete_files(self._manifest_file_name)

        self._zip_file.writestr(
            self._manifest_file_name,
            b'<?xml version="1.0" encoding="UTF-8"?>' + etree.tostring(manifest_xml)
        )

    def _add_mimetype(self):
        # NOTE: the mimetype entry should be the first one and not compressed, as per ETSI TS 102 918 (though optional)
        self._zip_file.writestr(self.MIME_TYPE_FILE, self.MIME_TYPE, ZIP_STORED)

    def _read_toc(self):
        """Read table of contents"""
        return self._zip_file.namelist()

    def _get_manifest_xml(self):
        if self._manifest is None:
            # Create a manifest from template
            with open(self.MANIFEST_TEMPLATE_FILE, 'rb') as f:
                self._manifest = etree.XML(f.read())
        return self._manifest

    @property
    def _manifest_file_name(self):
        return '{}/{}'.format(self.META_DIR, self.MANIFEST_FILE)

    def _enumerate_signatures(self):
        return [
            file_name
            for file_name in self._read_toc()
            if re.match(self.SIGNATURE_FILES_REGEX, file_name)
        ]

    def _delete_files(self, *file_names_to_delete):
        new_buf = io.BytesIO()
        new_zip_file = ZipFile(new_buf, 'a')
        file_names_to_delete = set(file_names_to_delete)
        for entry in self._zip_file.infolist():
            file_name = entry.filename
            if file_name in file_names_to_delete:
                file_names_to_delete.remove(file_name)
                continue

            with self.open_file(file_name) as f:
                new_zip_file.writestr(file_name, f.read(), entry.compress_type)

        self._zip_file.close()
        self._zip_buffer = new_buf
        self._zip_file = new_zip_file

    def _enumerate_data_files(self):
        """
        Yields 2-tuples of file name and mime_type
        """
        manifest_xml = self._get_manifest_xml()
        media_type_attr = self.MANIFEST_ATTR_MEDIA_TYPE
        full_path_attr = self.MANIFEST_ATTR_FULL_PATH

        for file_entry in manifest_xml.iterchildren():
            assert file_entry.tag == self.MANIFEST_TAG_FILE_ENTRY
            file_name = file_entry.attrib[full_path_attr]
            if file_name != '/':  # skip the 'root' entry
                yield file_name, file_entry.attrib[media_type_attr]

    def _verify_container_contents(self):
        self.verify_container()

        # Verify ZIP table of contents
        toc = self._read_toc()
        name = self.name
        if not toc:
            raise BDoc2FileError("Empty BDOC container '{}'".format(name))
        if toc[0] != self.MIME_TYPE_FILE:
            # Check that mimetype is the first entry.
            # NOTE: actually as per ETSI TS 102 918, MIME_TYPE_FILE is optional
            # neither is it explicitly stated as *the first entry*,
            # but digidoc software deems the opposite.
            raise BDoc2FileError(
                "BDOC container '{}' must contain '{}' as first file".format(name, self.MIME_TYPE_FILE)
            )
        if self._manifest_file_name not in toc:
            raise BDoc2FileError(
                "BDOC container '{}' must contain a '{}'".format(name, self.MANIFEST_FILE)
            )

        # Read the meta data
        with self.open_file(self.MIME_TYPE_FILE) as f:
            mime_type = f.read()
        if mime_type != self.MIME_TYPE:
            raise BDoc2FileError("Invalid mime type '{}' for BDOC container '{}'".format(mime_type, name))

        try:
            with self.open_file(self._manifest_file_name) as f:
                self._manifest = etree.XML(f.read())
        except Exception:
            raise BDoc2FileError("Failed to read manifest for BDOC container '{}'".format(name))

        toc_data_files = [
            file_name
            for file_name in toc[1:]  # the first one is MIME_TYPE_FILE, can be skipped
            if not file_name.startswith(self.META_DIR)
        ]

        manifest_data_files = [name for name, _ in self._enumerate_data_files()]

        if sorted(toc_data_files) != sorted(manifest_data_files):
            raise BDoc2FileError("Manifest file is out of date")
