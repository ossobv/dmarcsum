dmarcsum to analyze DMARC aggregate reports
===========================================

You may have your DMARC record set up like this::

    $ dig -t TXT _dmarc.example.com +short
    "v=DMARC1; p=reject; pct=10; fo=1;
      rua=mailto:jdoe+rua@example.org;
      adkim=s; aspf=s; ri=1209600;"

*(When the rua= or ruf= URI is not in the same domain, you'll also need a
TXT record to prove that you want mail:*
``dig -t txt example.com._report._dmarc.example.org +short`` ->
``"v=DMARC1"`` *)*

Now you should receive aggregate reports about *DKIM* and *SPF*
success/failure. In this case, around 10% of the mails would be
included. The reports are sent to the mailbox at *jdoe+rua@example.org*.
The format is *Authentication Failure Reporting Format* (AFRF), which is
an XML file found in the email.

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
            <domain>examoke.com</domain>
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

The *dmarcsum* tool aids in parsing these.

----

First you have it ``extract`` the mails from a *Maildir* style location::

    DMARC_MAILDIR=/var/mail/example.org/jdoe/.DMARC/cur \
      DMARC_TOADDR=jdoe+rua@example.org \
      DMARC_REPORTDIR=./reports-example.com \
      ./dmarcsum.py extract

This will populate the ``./reports-example.com`` directory with the XML files
found in the emails.

----

Then you can run ``summary`` or ``dump`` on the extracted XMLs::

    ./dmarcsum.py summary -r ./reports-example.com

This will give you a summary AFRF reports.

You can trim down which results you see, by specifying additional options. See
``dmarcsum.py --help`` for more info.
