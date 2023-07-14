#!/usr/bin/env python3
import gzip
import os
import sys
import warnings
from argparse import ArgumentParser, RawDescriptionHelpFormatter
from collections import defaultdict, namedtuple
from datetime import datetime
from email import message_from_binary_file
from ipaddress import ip_network
from io import StringIO
from mimetypes import guess_type
from xml.dom import minidom
from xml.etree import ElementTree
from yaml import safe_load
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


def write_xml(outfp, dom):
    if 1:
        # Expensive (6x!!) canonical + pretty writing.
        xml_string = ElementTree.tostring(dom.getroot())
        scratchpad = StringIO()
        # Run through canonicalize() to remove the whitespace.
        ElementTree.canonicalize(
            xml_data=xml_string, out=scratchpad,
            with_comments=True, strip_text=True,
            rewrite_prefixes=False)
        scratchpad.seek(0)
        # Run through minidom to add indentation.
        dom = minidom.parse(scratchpad)
        scratchpad = StringIO()
        dom.writexml(
            scratchpad, indent='', addindent='  ', newl='\n', encoding='utf-8')
        # Loop over lines and add idx comments. This annotates all but the
        # first equal 2nd level element, like:
        #   <record>
        #   <record><!-- #1 -->
        #   <record><!-- #2 -->
        #   ...
        scratchpad.seek(0)
        indexes = {}
        for line in scratchpad:
            if (line.startswith('  <') and line.endswith('>\n') and
                    line[3] != '/'):
                if line in indexes:
                    indexes[line] += 1
                    line = f'{line[0:-1]}<!-- #{indexes[line]} -->\n'
                else:
                    indexes[line] = 0
            outfp.write(line)
    else:
        # Cheap writing.
        dom.write(
            outfp, encoding='unicode', xml_declaration=True,
            short_empty_elements=False)


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
        msg = email.parsed

        # Check _some_ credentials on the mails.
        # Should validate DKIM here..
        # received_spf = msg['received-spf']  # gets the topmost one (right?)
        # if received_spf.startswith('Pass '):
        #     pass
        # elif received_spf.startswith('None '):
        #     warn(f'no SPF configured for {email.filename!r}')
        # else:
        #     assert False, (email, msg['received-spf'])

        # Write attachments.
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

        with open(tmp_filename, mode='w', encoding='utf-8') as fp:
            sudo_chown(fp)
            write_xml(fp, dom)
        os.utime(tmp_filename, (email.mtime, email.mtime))

        os.rename(tmp_filename, new_filename)
        return new_filename


class ReportOrg(namedtuple('ReportOrg', 'org_suffix email_suffix')):
    @classmethod
    def from_report_dom(cls, report_dom):
        org_suffix = report_dom.findtext('report_metadata/org_name')
        if '.' in org_suffix and len(org_suffix.split('.', 2)) > 2:
            org_suffix = '...' + '.'.join(org_suffix.rsplit('.', 2)[-2:])

        email_suffix = report_dom.findtext('report_metadata/email')
        email_suffix = email_suffix.rsplit('@', 1)[-1]
        email_suffix = '...' + '.'.join(email_suffix.rsplit('.', 2)[-2:])
        return cls(org_suffix=org_suffix, email_suffix=email_suffix)


class ReportRecord(namedtuple('RecordRecord', (
        'source_file source_record org period_begin period_end count '
        'source_ip env_from env_to hdr_from dkim spf'))):
    @classmethod
    def from_report_dom(cls, report, record_idx, dom_record):
        dkim_ok = dom_record.findtext('row/policy_evaluated/dkim')
        assert dkim_ok in ('pass', 'fail'), (report.name, dkim_ok)
        dkim_ok = (dkim_ok == 'pass')

        spf_ok = dom_record.findtext('row/policy_evaluated/spf')
        assert spf_ok in ('pass', 'fail'), (report.name, spf_ok)
        spf_ok = (spf_ok == 'pass')

        source_ip = dom_record.findtext('row/source_ip')
        assert source_ip, (report.name, source_ip)

        count = int(dom_record.findtext('row/count'))
        assert count > 0, (report.name, count)

        # Not sure when envelope_from is set. Various reports do not
        # include this. We'll mark the env_from as '*' for now.
        # For the empty env_from, we'll assume '<>'. Not sure if this is
        # correct.
        env_from = dom_record.findtext('identifiers/envelope_from')
        if env_from == '':
            env_from = '<>'
        elif env_from is None:
            env_from = '*'  # we don't know

        env_to = dom_record.findtext('identifiers/envelope_to')
        assert env_to != '*', report
        if env_to is None:
            env_to = '*'

        hdr_from = dom_record.findtext('identifiers/header_from')
        # XXX: assert hdr_from == report.domain, (hdr_from, report.domain)

        return cls(
            source_file=report.name,
            source_record=record_idx,
            org=report.org,
            period_begin=report.period_begin,
            period_end=report.period_end,
            count=count,
            source_ip=source_ip,
            env_from=env_from,
            env_to=env_to,
            hdr_from=hdr_from,
            dkim=dkim_ok,
            spf=spf_ok,
        )

    # TODO: improve repr()/str() output by a lot..


class Report:
    @classmethod
    def from_filename(cls, filename):
        with open(filename, 'rb') as fp:
            dom = ElementTree.parse(fp)
        return cls(dom, name=os.path.basename(filename))

    def __init__(self, dom, name):
        self._dom = dom
        self.name = name
        self.org = ReportOrg.from_report_dom(dom)
        self.domain = dom.findtext('policy_published/domain')
        assert self.domain, (name, self.domain)
        self._period_begin = None
        self._period_end = None

    @property
    def period_begin(self):
        if self._period_begin is None:
            self._period_begin = datetime.fromtimestamp(int(
                self._dom.findtext('report_metadata/date_range/begin')))
        return self._period_begin

    @property
    def period_end(self):
        if self._period_end is None:
            self._period_end = datetime.fromtimestamp(int(
                self._dom.findtext('report_metadata/date_range/end')))
        return self._period_end

    def get_records(self):
        records = self._dom.findall('record')

        for idx, record in enumerate(records):
            record = ReportRecord.from_report_dom(self, idx, record)
            yield record

    def __repr__(self):
        return f'<Report({self.name!r})>'


class ReportSummary:
    def __init__(self):
        self._period_begin = datetime(2038, 1, 1)
        self._period_end = datetime(1970, 1, 1)
        self._domain = None
        self._records = []
        self._by_org = {}
        self._by_record = {
            'source-ip': defaultdict(list),
            'known-ip': defaultdict(list),
            'env-from': defaultdict(list),
            'env-to': defaultdict(list),
            'hdr-from': defaultdict(list),
        }
        self._known_ips = {}
        self._both_good_counts = 0
        self._dkim_good_counts = 0
        self._spf_good_counts = 0
        self._both_bad_counts = 0
        self._both_good = []
        self._dkim_good = []
        self._spf_good = []
        self._both_bad = []

    def set_known_ips(self, dict_with_lists):
        self._known_ips = {}
        for key, nets in dict_with_lists.items():
            if key:  # skip the empty key
                for net in nets:
                    net = ip_network(net)
                    self._known_ips[net] = key

    def get_known_ip(self, ip):
        net = ip_network(ip)
        for possible_net in self._known_ips.keys():
            if (net.__class__ == possible_net.__class__ and
                    net.subnet_of(possible_net)):
                return self._known_ips[possible_net]  # "name"
        return ''

    def add(self, report, args):
        # We only expect to handle a single domain at the moment.
        if self._domain != report.domain:
            assert self._domain is None, (self._domain, report)
            self._domain = report.domain

        added = []
        for record in report.get_records():
            if self._maybe_add_record(record, args):
                added.append(record)

        if not added:
            return

        # Add to global lists.
        try:
            self._by_org[report.org].extend(added)
        except KeyError:
            self._by_org[report.org] = added

        self._period_begin = min(report.period_begin, self._period_begin)
        self._period_end = max(report.period_end, self._period_end)

    def _maybe_add_record(self, record, args):
        if args.dkim is not None:
            if record.dkim is not args.dkim:
                return False
        if args.spf is not None:
            if record.spf is not args.spf:
                return False

        known_ip = self.get_known_ip(record.source_ip)
        if args.source_ip and args.source_ip not in (
                known_ip, record.source_ip):
            return False

        self._records.append(record)

        if record.dkim is record.spf is True:
            self._both_good_counts += record.count
            self._both_good.append(record)
        elif record.dkim:
            self._dkim_good_counts += record.count
            self._dkim_good.append(record)
        elif record.spf:
            self._spf_good_counts += record.count
            self._spf_good.append(record)
        else:
            self._both_bad_counts += record.count
            self._both_bad.append(record)

        self._by_record['source-ip'][record.source_ip].append(record)
        self._by_record['known-ip'][known_ip].append(record)
        self._by_record['env-from'][record.env_from].append(record)
        self._by_record['env-to'][record.env_to].append(record)
        self._by_record['hdr-from'][record.hdr_from].append(record)
        return True

    def print_summary(self):
        def print_dict(title, d):
            print(title)
            for idx, (name, items) in enumerate(
                    sorted(d.items(), key=(
                        lambda kv: (-len(kv[1]), kv[0])))):
                print(f'- {len(items):6d}  {name}')
                if idx >= 15:
                    print('- ...')
                    break
            print()

        print(f'Dates: {self._period_begin} .. {self._period_end}')
        print(f'Records: {len(self._records)}')
        print(f'DKIM&SPF:   {len(self._both_good)} ({self._both_good_counts})')
        print(f'DKIM&!SPF:  {len(self._dkim_good)} ({self._dkim_good_counts})')
        print(f'!DKIM&SPF:  {len(self._spf_good)} ({self._spf_good_counts})')
        print(f'!DKIM&!SPF: {len(self._both_bad)} ({self._both_bad_counts})')
        print()

        print_dict('By organisation:', self._by_org)
        for key in ('source-ip', 'known-ip', 'env-from', 'env-to', 'hdr-from'):
            print_dict(f'By {key}:', self._by_record[key])


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
            # TODO: improve to-addr matching without making it expensive
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

    # find /var/mail/example.com/.INBOX/cur -type f | grep -l "To: $to_addr"
    filenames = os.listdir(mail_dirname)
    filenames.sort()

    print('Extracting:')
    # TODO: disable progressbar if stdout is not a tty?
    bar = ProgressBar(maxval=len(filenames)).start()

    for idx, f in enumerate(filenames, 1):
        mail_filename = os.path.join(mail_dirname, f)

        # We don't expect directories here. Nor do we expect files where we
        # do not have read permissions
        with open(mail_filename, 'rb') as fp:
            email = EmailWrapper.from_filename_fp(mail_filename, fp)
            if is_candidate(email):
                extractor.extract(email)

        bar.update(idx)
    bar.finish()


def _make_summary(report_dirname, args):
    filenames = os.listdir(report_dirname)
    filenames.sort()

    summary = ReportSummary()

    if args.known_ips:
        with open(args.known_ips) as fp:
            summary.set_known_ips(safe_load(fp)['known_ips'])

    print('Summarizing:')
    # TODO: disable progressbar if stdout is not a tty?
    bar = ProgressBar(maxval=len(filenames)).start()

    for idx, filename in enumerate(filenames, 1):
        report = Report.from_filename(os.path.join(report_dirname, filename))
        if args.since and report.period_end < args.since:
            pass
        elif args.until and report.period_begin >= args.until:
            pass
        else:
            summary.add(report, args)
        bar.update(idx)
    bar.finish()

    return summary


def run_dump(report_dirname, args):
    summary = _make_summary(report_dirname, args)
    for record in summary._records:
        print(record)


def run_summary(report_dirname, args):
    summary = _make_summary(report_dirname, args)
    summary.print_summary()


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


def parse_date(s):
    return datetime(*[int(i) for i in s.split('-')])


def parse_passfail(s):
    assert s in ('pass', 'fail'), s
    return s == 'pass'


def main():
    parser = ArgumentParser(
        formatter_class=RawDescriptionHelpFormatter,
        description='''\
Summarize DMARC reports. This is a two step process:

First the XML should be fetched from Maildir storage (local IMAP?).
Then the XML can be read and summarized or dumped to stdout.

- extract: get the reports from a Maildir, requires
  DMARC_MAILDIR, DMARC_TOADDR, DMARC_REPORTDIR
- summary: read the reports fromm DMARC_REPORTDIR, print summary
- dump: read the reports from DMARC_REPORTDIR, output all records
''')
    subparsers = parser.add_subparsers(dest='command', help='command help')

    parser_extract = subparsers.add_parser(
        'extract', help='Extract files from Maildir')
    (parser_extract,)  # touch for PEP
    parser_dump = subparsers.add_parser(
        'dump', help='Parse DMARC XML reports and dump listing')
    parser_summary = subparsers.add_parser(
        'summary', help='Parse DMARC XML reports and show summary')

    for command_that_parses in (parser_dump, parser_summary):
        command_that_parses.add_argument('-S', '--since', type=parse_date)
        command_that_parses.add_argument('-U', '--until', type=parse_date)
        command_that_parses.add_argument('--dkim', type=parse_passfail)
        command_that_parses.add_argument('--spf', type=parse_passfail)
        # TODO: add more filters? --header-from? --domain? --env-from?
        # TODO: split up known-ip from source-ip. Allow multiple source-ip?
        command_that_parses.add_argument('--source-ip', type=str)  # str?
        # YAML with 'known_ips: {"name": [ip1, ip2, ip3]}'
        # TODO: this needs documentation
        command_that_parses.add_argument('--known-ips', type=str)

    args = parser.parse_args()

    if args.command == 'extract':
        # FIXME: don't use (only) ENV for these values..
        mail_dirname = os.environ['DMARC_MAILDIR']
        toaddr = os.environ['DMARC_TOADDR']
        dest_dirname = os.environ['DMARC_REPORTDIR']
        run_extract(
            mail_dirname=mail_dirname, dest_dirname=dest_dirname,
            toaddr=toaddr)

    elif args.command == 'dump':
        # FIXME: don't use (only) ENV for these values..
        report_dirname = os.environ['DMARC_REPORTDIR']
        run_dump(report_dirname=report_dirname, args=args)

    elif args.command == 'summary':
        # FIXME: don't use (only) ENV for these values..
        report_dirname = os.environ['DMARC_REPORTDIR']
        run_summary(report_dirname=report_dirname, args=args)

    elif args.command is None:
        parser.print_usage()

    else:
        print('FIXME', args)
        exit(1)


if __name__ == '__main__':
    main()
