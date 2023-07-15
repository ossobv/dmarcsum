dmarcsum CLI to bulk analyze DMARC aggregate reports
====================================================

*dmarcsum is your command line tool to extract DMARC reports from email
and quickly sift through thousands of reports.*

If you're like me, you may have enabled *DMARC* on your maildomain, but
delayed looking at the reports send by *Outlook* and *Gmail*. This tool
aids in making sense of those reports.


-----------
Quick usage
-----------

Extract *Authentication Failure Reporting Format* report XML files from
your *Maildir format* INBOX?

.. code-block:: console

    $ sudo DMARC_MAILDIR=/var/mail/example.com/jdoe/.DMARC/cur \
        DMARC_TOADDR=jdoe+rua+example.com@example.org \
        DMARC_REPORTDIR=./reports-example.com \
        dmarcsum.py extract

This produces a bunch of XML files in ``./reports-example.com``.

They can now be parsed using ``dmarcsum.py summary`` or ``dmarcsum.py dump``.

.. code-block:: console

    $ dmarcsum.py summary -r ./reports-example.com
    Stats:
    - dates: 2023-01-31 01:00:00 .. 2023-07-14 01:59:59
      (note: some reports can have coarse/wide date ranges)
    - volume:   3742 count (988 records)
    - DMARC:    3067 pass,    675 fail,  82.0% compliance
    ...
    By source-ip:
    -    2753 (   484)  11.22.33.44
    -     481 (   150)  fe80::1:2:3:4
    -      87 (    62)  10.20.30.40
    ...

See the records, but only those that failed both DKIM and SPF:

.. code-block:: console

    $ dmarcsum.py dump -r ./reports-example.com --dkim=fail --spf=fail
    ...
    2023-02-02+1d +DKIM -SPF count=2 env-from=<example.com> env-to=* hdr-from=<example.com> source=<1675395037.M25595P1620004.example.com,*#0>
    2023-02-03+1d +DKIM -SPF count=1 env-from=<example.com> env-to=* hdr-from=<example.com> source=<1675480249.M805978P2141872.example.com,*#0>
    2023-02-03+1d +DKIM -SPF count=1 env-from=<other-domain.com> env-to=* hdr-from=<example.com> source=<1675505382.M783723P2283587.example.com,*#0>
    ...

From the dumped records, we can go back to the source XML:

.. code-block:: console

    $ echo reports-example.com/1675505382.M783723P2283587.example.com,*
    reports-example.com/1675505382.M783723P2283587.example.com,amazonses.com!example.com!1675382400!1675468800.xml

There the *#0th* ``<record>`` entry can be manually inspected.


-------------------
DMARC example setup
-------------------

You may have your *DMARC* record set up like this::

    $ dig -t TXT _dmarc.example.com +short
    "v=DMARC1; p=reject; pct=10; fo=1;
      rua=mailto:jdoe+rua+example.com@example.org;
      adkim=s; aspf=s; ri=1209600;"

*(When the rua= or ruf= URI is not in the same domain, you'll also need a
TXT record to prove that you want mail:*
``dig -t txt example.com._report._dmarc.example.org +short`` ->
``"v=DMARC1"`` *)*

Now you should receive aggregate reports about *DKIM* and *SPF*
success/failure. In this case, a sample of around 10% of the mails would be
included. The reports are sent to the mailbox at
*jdoe+rua+example.com@example.org*.  The format is *Authentication
Failure Reporting Format* (AFRF), which is an XML file found in the
email.

Those AFRF XMLs might look like this:

.. code-block:: xml

    <?xml version="1.0" encoding="utf-8"?>
    <feedback>
      <report_metadata>
        <org_name>google.com</org_name>
        <email>noreply-dmarc-support@XXX</email>
        <report_id>4783348139951359342</report_id>
        <date_range>
          <begin>1686528000</begin>
          <end>1686614399</end>
        </date_range>
      </report_metadata>
      <policy_published>
        <domain>example.com</domain>
        <adkim>s</adkim>
        <aspf>s</aspf>
        <p>reject</p>
        <sp>reject</sp>
        <pct>10</pct>
        <np>reject</np>
      </policy_published>
      <record>
        <row>
          <source_ip>1.2.3.4</source_ip>
          <count>1</count>
          <policy_evaluated>
            <disposition>quarantine</disposition>
            <dkim>fail</dkim>
            <spf>fail</spf>
            <reason>
              <type>forwarded</type>
              <comment>looks forwarded, not quarantined for DMARC</comment>
            </reason>
            <reason>
              <type>sampled_out</type>
              <comment/>
            </reason>
          </policy_evaluated>
        </row>
        <identifiers>
          <header_from>example.com</header_from>
        </identifiers>
        <auth_results>
          <dkim>
            <domain>example.com</domain>
            <result>fail</result>
            <selector>mail2019</selector>
          </dkim>
          <spf>
            <domain>mxforwarder.de</domain>
            <result>pass</result>
          </spf>
        </auth_results>
      </record>
      ...
    </feedback>

*dmarcsum* aids in parsing these.

----

*This is not an end product. It's a start. Use this to get a grip on the
first stages of DMARC deployment.*
