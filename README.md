dspam-milter
--------------------

[pymilter](http://www.bmsi.com/python/milter.html)-based daemon script to
classify email using [dspam](http://dspam.sourceforge.net/) daemon (and its
dspamc client).

Main feature is that it is designed to *never* reject, drop or "quarantine"
email, only add X-DSPAM-Result header (as returned by `dspamc --deliver=summary`).

User is assumed to be smart enough to e.g. add sieve rules to act upon this
header (and maybe others, e.g. spf, dkim, ...) as they see fit.

All documented dspam setups seem to use either dspam as a delivery agent proxy
or mail transport (with later mail re-injection), which assumes a lot of trust
in that dspam process won't crash, fail to run proper delivery agent (or
sendmail), be misconfigured or otherwise drop or mangle messages handled to it.

This script assumes no extra trust in dspam daemon, as any failure there will
just result in X-DSPAM-Result header not being appended or TEMPFAIL result (with
message generally left in queue) in case of script exception.

Another design principle is to use shipped "dspamc" client and not try to
connect, authenticate over and implement DMTP or LMTP protocol to pass messages
to a daemon, resulting in very simple and robust script (100-lines instead of
e.g. 1k lines of [pydspam](https://github.com/whyscream/pydspam)).


Usage
--------------------

See `dspam-milter.py -h` output for the list of CLI options:

	usage: dspam-milter.py [-h] [-t seconds] [--debug] [socket]

	Ad-hoc dspam milter that does --deliver=summary and only adds result as
	header, never rejecting or dropping messages.

	positional arguments:
	  socket                libmilter-format socket spec to listen on (default:
	                        local:/tmp/dspam_milter.sock). Examples:
	                        local:/tmp/dspam_milter.sock, inet:1234@localhost,
	                        inet6:1234@localhost

	optional arguments:
	  -h, --help            show this help message and exit
	  -t seconds, --timeout seconds
	                        Number of seconds the MTA should wait for a response
	                        before considering this milter dead (default: 600).
	  --debug               Verbose operation mode.

Expected to be run from modern init like systemd, upstart, runit or whatever
other process manager.
