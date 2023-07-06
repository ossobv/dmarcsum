#!/usr/bin/env python3
import gzip
import os
import sys
import warnings
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from email import message_from_binary_file
from mimetypes import guess_type
from xml.etree import ElementTree
from zipfile import BadZipFile, ZipFile

from progressbar import ProgressBar


class WARN(UserWarning):
    pass


def warn(message):
    warnings.warn(message, category=WARN, stacklevel=2)


def sudo_chown(file):
    uid, gid = os.environ.get('SUDO_UID'), os.environ.get('SUDO_GID')
    if uid is None or gid is None:
        return
    if hasattr(file, 'fileno'):
        os.fchown(file.fileno(), int(uid), int(gid))
    elif isinstance(file, int):
        os.fchown(file, int(uid), int(gid))
    else:
        os.chown(file, int(uid), int(gid))


def zip_open_the_only_file(filename):
    # Closing the containing zipfile appears to work.
    with ZipFile(filename, 'r') as zipped:
        contents = zipped.namelist()
        assert len(contents) == 1, contents
        fp = zipped.open(contents[0])
    return fp


def temp_filename(filename):
    try:
        dir_, base = filename.rsplit('/', 1)
    except ValueError:
        dir_, base = '.', filename
    return f'{dir_}/.{base}.tmp'


class EmailWrapper:
    @classmethod
    def from_filename_fp(cls, filename, fp):
        return cls(fp=fp, filename=filename)

    def __init__(self, filename=None, fp=None, mtime=None):
        self._filename = filename
        self._fp = fp
        self._mtime = mtime
        self._parsed = None

    @property
    def filename(self):
        if not self._filename:
            self._filename = self._fp.name
        return self._filename

    @property
    def basename(self):
        return self.filename.rsplit('/', 1)[-1]

    @property
    def staticname(self):
        """
        Maildir mails look like:

            1688475441.M408400P2224990.mail.example.com,S=13918,W=14139:2,

        Return only '1688475441.M408400P2224990.mail.example.com' because the
        tail is mutable (marking read/unread).
        """
        return self.basename.split(',', 1)[0]

    @property
    def mtime(self):
        if not self._mtime:
            self._mtime = os.fstat(self._fp.fileno()).st_mtime
        return self._mtime

    def get_header(self, key):
        """
        Cheaper than doing message_from_binary_file at once

        Also a lot cheaper than doing:

            email.parser.BytesParser().parse(self._fp, headersonly=True)['to']

        Tested with Python3.8.10 on Jammy. Timings: 1s vs. 6s vs. 9s when
        filtering 600 mails from a 7000 mail mailbox.
        """
        self._fp.seek(0)

        needle = f'{key}: '.encode('ascii')
        found = []

        for line in self._fp:
            if line.startswith((b'\r', b'\n')):
                break
            elif line.startswith(needle):
                found.append(line)
            elif found:
                if line.startswith((b' ', b'\t')):
                    found.append(line)
                else:
                    return b''.join(found)

        return None

    @property
    def parsed(self):
        """
        More expensive, but a lot more useful
        """
        if self._parsed is None:
            self._fp.seek(0)
            self._parsed = message_from_binary_file(self._fp)
        return self._parsed

    def __repr__(self):
        return f'<EmailWrapper(filename={self._filename})>'


class MailExtractor:
    """
    Feed the MailExtractor mails and it will extract dmarc XML reports into
    dest_dirname.
    """
    ACCEPTED_MIME = [
        'application/gzip',
        'application/x-gzip',
        'application/zip',
        'application/x-zip-compressed',
        'application/octet-stream',
    ]
    MIME_GZIP = ['application/gzip', 'application/x-gzip']
    MIME_ZIP = ['application/zip', 'application/x-zip-compressed']
    MIME_TRASH = ['application/octet-stream', 'text/xml']

    @classmethod
    def split_attachment_filename(cls, filename):
        """
        The extracted files look like:

            1688335240.M679518P1248043.mail.example.com,outlook.com!exam..xml

        Returns:

            1688335240.M679518P1248043.mail.example.com
            +
            outlook.com!exam..xml

        We use a comma separator so we can find existing blobs by the mailname.
        """
        assert '/' not in filename, filename
        assert ',' in filename, filename
        return filename.split(',', 1)

    @classmethod
    def join_attachment_filename(cls, staticname, attachment_name):
        """
        The source files look like:

            1688475441.M408400P2224990.mail.example.com[,S=13918,W=14139:2,]
            +
            outlook.com!example.com!1688248804!1688335203.xml.gz

        Returns:

            1688475441.M408400P2224990.mail.example.com,outlook.com!e...xml.gz

        We use a comma separator so we can find existing blobs by the mailname.
        """
        assert ',' not in staticname, (staticname, attachment_name)
        assert '/' not in staticname, (staticname, attachment_name)
        assert '/' not in attachment_name, (staticname, attachment_name)
        return ','.join([staticname, attachment_name])

    @classmethod
    def find_in_maildir(cls, mail_dirname, is_candidate=(lambda email: True)):
        """
        find /var/mail/example.com/.INBOX/cur -type f | grep -l "To: $to_addr"

        The is_candidate function might look like:

            return (b'dmarcreports@example.com' in email.get_header('To'))
        """
        filenames = os.listdir(mail_dirname)
        bar = ProgressBar(maxval=len(filenames)).start()

        for idx, f in enumerate(filenames, 1):
            mail_filename = os.path.join(mail_dirname, f)

            # We don't expect directories here. Nor do we expect files where we
            # do not have read permissions
            with open(mail_filename, 'rb') as fp:
                email = EmailWrapper.from_filename_fp(mail_filename, fp)
                if is_candidate(email):
                    yield email

            bar.update(idx)
        bar.finish()

    def __init__(self, dest_dirname):
        """
        Constructor, takes the target dir
        """
        if not os.path.isdir(dest_dirname):
            os.makedirs(dest_dirname)
            sudo_chown(dest_dirname)

        self._dest_dirname = dest_dirname

    def extract(self, email):
        """
        Takes an EmailWrapper and saves the relevant attachments
        """
        # Write attachments.
        msg = email.parsed
        files_written = []
        if msg.is_multipart():
            for attach in msg.get_payload():
                if attach.get_content_type() in self.ACCEPTED_MIME:
                    files_written.append(self.save_attachment(email, attach))
        else:
            files_written.append(self.save_attachment(email, msg))

        assert files_written, (email, 'expected at least one attachment')

        # Do a pass on the written attachments, doing any necessary unzip work.
        keep = set()
        try:
            for filename in files_written[:]:  # copy, because we mutate it
                new_filename = self.unpack_attachment(email, filename)
                files_written.append(new_filename)
                keep.add(new_filename)
        except Exception:
            # Clean up everything. Let user restart processing from zero.
            warn(f'Cleaning all {files_written}')
            for filename in files_written:
                os.unlink(filename)
            raise

        # Remove zipped/source files.
        for filename in files_written:
            if filename not in keep:
                os.unlink(filename)

    def save_attachment(self, email, attachment):
        attach_name = attachment.get_filename()
        if not attach_name:
            # Maybe there is a duplicate header? We've seen this in
            # mails from 'no-reply@*.mimecastreport.com'.
            attachment._headers = [
                (k, v) for k, v in attachment._headers
                if not (k == 'Content-Disposition' and v == 'attachment')]
            attach_name = attachment.get_filename()
            assert attach_name, (email, attach_name)

        assert '/' not in attach_name, (email, attach_name)
        assert not attach_name.startswith('.'), (email, attach_name)
        basename = self.join_attachment_filename(email.staticname, attach_name)
        dest = os.path.join(self._dest_dirname, basename)

        with open(dest, 'xb') as fp:  # exclusive write, fail if exists
            sudo_chown(fp)
            fp.write(attachment.get_payload(decode=True))
        os.utime(dest, (email.mtime, email.mtime))

        return dest

    def unpack_attachment(self, email, filename):
        if filename.endswith('.xml'):
            new_filename = filename
        elif filename.endswith(('.xml.gz', '.xml.zip')):
            new_filename = filename.rsplit('.', 1)[0]
        elif (filename.endswith(('.zip'),) and
                len(filename.rsplit('.', 2)[-2]) > 5):  # no .suffix.suffix
            new_filename = f'{filename.rsplit(".", 1)[0]}.xml'
        else:
            assert False, ('unexpected filename', email, filename)
        tmp_filename = temp_filename(new_filename)

        fp = None
        mime, encoding = guess_type(filename)
        assert mime, (email, filename, mime, encoding)

        if encoding == 'gzip' or mime in self.MIME_GZIP:
            fp = gzip.open(filename, 'rb')
        elif mime in self.MIME_ZIP:
            fp = zip_open_the_only_file(filename)
        elif mime in self.MIME_TRASH:
            try:
                fp = zip_open_the_only_file(filename)
            except BadZipFile:
                fp = gzip.open(filename, 'rb')
        else:
            assert False, (email, filename, mime, encoding)

        try:
            # Somewhat expensive. But a good check..
            dom = ElementTree.parse(fp)
        finally:
            fp.close()

        with open(tmp_filename, 'wb') as fp:
            sudo_chown(fp)
            dom.write(
                fp, encoding='utf-8', xml_declaration=True,
                short_empty_elements=False)
        os.utime(tmp_filename, (email.mtime, email.mtime))

        os.rename(tmp_filename, new_filename)
        return new_filename


def run_extract(mail_dirname, dest_dirname, toaddr):
    extractor = MailExtractor(dest_dirname)

    already_extracted_staticnames = set(
        extractor.split_attachment_filename(name)[0]
        for name in os.listdir(dest_dirname))
    bin_toaddr = toaddr.encode('ascii')

    def is_candidate(email):
        if email.staticname in already_extracted_staticnames:
            return False

        if 1:  # v-- cheap
            # XXX: improve to-addr matching without making it expensive
            to = email.get_header('To')
            if to is None or not to.strip():
                warn(f'{email.filename!r} has no To header')
                return False
            assert to, (email.filename, to)  # 'None' for broken e-mail?
            if bin_toaddr not in to:
                return False

        else:  # v-- expensive
            to = email.parsed['to']
            if to is None or not to.strip():
                warn(f'{email.filename!r} has no To header')
                return False
            if toaddr not in email.parsed['to']:
                return False

        assert toaddr in email.parsed['to'], email.parsed['to']
        return True

    print('Extracting:')
    for fp in extractor.find_in_maildir(
            mail_dirname, is_candidate=is_candidate):
        extractor.extract(fp)


def formatwarning(message, category, filename, lineno, line=None):
    """
    Override default Warning layout, from:

        /PATH/TO/APP.py:326: UserWarning:
            [Errno 2] No such file or directory: '/0.d/05.d'
          warnings.warn(str(e))

    To:

        APP.py:330: UserWarning:
            [Errno 2] No such file or directory: '/0.d/05.d'
    """
    if sys.stderr.isatty():
        erase_line = '\x1b[2K\r'
    else:
        erase_line = ''
    basename = filename.rsplit('/', 1)[-1]
    cat = category.__name__
    return f'{erase_line}{basename}:{lineno}: {cat}: {message}\n'
warnings.formatwarning = formatwarning  # noqa


def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='''\
Summarize DMARC reports. This is a three step process:

- extract: get the reports from a Maildir, requires
  DMARC_MAILDIR, DMARC_TOADDR, DMARC_REPORTDIR
- parse: read the reports from DMARC_REPORTDIR, writes to sqlite
- summary: write a summary
''')
    subparsers = parser.add_subparsers(dest='command', help='command help')
    parser_extract = subparsers.add_parser(
        'extract', help='Extract files from Maildir')
    parser_parse = subparsers.add_parser(
        'parse', help='Parse DMARC XML reports')
    parser_summary = subparsers.add_parser(
        'summary', help='Generate summary')
    (parser_extract, parser_parse, parser_summary)  # touch for PEP

    args = parser.parse_args()
    if args.command == 'extract':
        # FIXME: hardcoded values
        mail_dirname = os.environ['DMARC_MAILDIR']
        toaddr = os.environ['DMARC_TOADDR']
        dest_dirname = os.environ['DMARC_REPORTDIR']
        run_extract(
            mail_dirname=mail_dirname, dest_dirname=dest_dirname,
            toaddr=toaddr)

    elif args.command is None:
        parser.print_usage()

    else:
        print('XXX', args)
        exit(1)


if __name__ == '__main__':
    main()
