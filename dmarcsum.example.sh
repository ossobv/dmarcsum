#!/bin/sh

# First do some kind of IMAP fetch?
#offlineimap -l offlineimap.log -c offlineimaprc

# Then run the tool (you can use sudo(1) do reach into /var/mail).
DMARC_MAILDIR=/var/mail/example.org/jdoe/.DMARC/cur \
DMARC_TOADDR=jdoe+rua+example.com@example.org \
DMARC_REPORTDIR=./reports-jdoe \
./dmarcsum.py "$@"
