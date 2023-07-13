#!/bin/sh

# First do some kind of IMAP fetch?
#offlineimap -l offlineimap.log -c offlineimaprc

# Then run the tool (you can use sudo(1) do reach into /var/mail).
DMARC_MAILDIR=/var/mail/example.com/jdoe/.DMARC-Reports/cur \
DMARC_TOADDR=jdoe+dmarcreports@example.com \
DMARC_REPORTDIR=./reports-jdoe \
./dmarcsum.py "$@"
