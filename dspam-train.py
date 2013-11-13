#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function

import itertools as it, operator as op, functools as ft
from subprocess import Popen, PIPE
from os.path import normpath, join, isdir
from datetime import datetime, timedelta
import os, sys, re, mailbox, stat, tempfile, shutil


try: from dateutil import parser as dateutil_parser
except ImportError: dateutil_parser = None

_short_ts_days = dict(y=365.25, yr=365.25, mo=30.5, w=7, d=1)
_short_ts_s = dict(h=3600, hr=3600, m=60, min=60, s=1, sec=1)

def _short_ts_regexp():
	'''Generates regexp for parsing of
		shortened relative timestamps, as shown in the table.'''
	ago_re = list('^-?')
	for k in it.chain(_short_ts_days, _short_ts_s):
		ago_re.append(r'(?P<{0}>\d+{0}\s*)?'.format(k))
	ago_re.append(r'(\s+ago\b)?$')
	return re.compile(''.join(ago_re), re.I | re.U)
_short_ts_regexp = _short_ts_regexp()

def parse_timestamp(val):
	'''Match time either in human-readable format (as accepted by dateutil),
		or same time-offset format, as used in the table (e.g. "NdMh ago", or just "NdMh").'''
	if not val or val == '-': return None

	val = val.replace('_', ' ')

	# Try to parse time offset in short format, similar to how it's presented
	match = _short_ts_regexp.search(val)
	if match:
		delta = list()
		parse_int = lambda v: int(''.join(c for c in v if c.isdigit()))
		for units in [_short_ts_days, _short_ts_s]:
			val = 0
			for k, v in units.iteritems():
				try:
					if not match.group(k): continue
					n = parse_int(match.group(k))
				except IndexError: continue
				val += n * v
			delta.append(val)
		return datetime.now() - timedelta(*delta)

	# Fallback to other generic formats
	ts = None
	if dateutil_parser: # try dateutil module, if available
		# dateutil fails to parse textual dates like "yesterday"
		try: ts = dateutil_parser.parse(val)
		except ValueError: pass
	if not ts:
		# coreutils' "date" parses virtually everything, but is more expensive to use
		with open(os.devnull, 'w') as devnull:
			proc = Popen(['date', '+%s', '-d', val], stdout=PIPE, stderr=devnull)
			val = proc.stdout.read()
			if not proc.wait(): ts = datetime.fromtimestamp(int(val.strip()))

	if ts: return ts
	raise ValueError('Unable to parse date/time string: {0}'.format(val))


def box_path(box, path):
	path = normpath(path).replace(os.sep, '.').strip('.')
	if not path: return box
	path = box.get_folder(path)
	path._factory = None # to return proper MaildirMessage instances
	return path

def path_process(path, seen_only=True, ts_min=None, ts_max=None, size_max=None):
	# Don't use mailbox module msg handling here,
	#  as it parses the message bodies, which we don't need to do
	for subdir in ['cur'] if not seen_only else ['new', 'cur']:
		path_dir = join(path._path, 'cur')
		if not isdir(path_dir): continue

		for msg in os.listdir(path_dir):
			if msg.startswith('.'): continue
			msg_path = join(path_dir, msg)
			try:
				msg_stat = os.stat(msg_path)
				if not stat.S_ISREG(msg_stat.st_mode):
					raise AssertionError
			except (OSError, IOError, AssertionError): continue

			if size_max and msg_stat.st_size > size_max: continue

			if not seen_only:
				info = msg.split(':', 2)[1]
				assert info.startswith('2,'), msg_path
				flags = info.split(',', 2)[1]
				if 'S' not in flags: continue

			if ts_min or ts_max:
				ts = datetime.fromtimestamp(msg_stat.st_mtime)
				if (ts_max and ts > ts_max) or (ts_min and ts < ts_min): continue

			yield msg_path


class DSpamError(Exception): pass

def dspamc( msg_path, tag, train=False,
		user=None, msg_src=None, msg_dst=None, retrain=False,
		_tag_ids=dict(
			spam=({'Spam', 'Blacklisted'}, 'spam'),
			ham=({'Innocent', 'Whitelisted'}, 'innocent')) ):
	'Returns dspam summary header value or force-trains dspam on class mismatch.'
	assert not tag or tag in ['spam', 'ham'], tag

	cmd = ['dspamc', '--deliver=summary']
	if user: cmd.extend(['--user', user])
	if msg_dst:
		if isinstance(msg_dst, basestring): msg_dst = [msg_dst]
		cmd.extend(['--rcpt-to', ' '.join(sorted(msg_dst))])
	if msg_src:
		assert isinstance(msg_src, basestring), [type(msg_src), msg_src]
		cmd.extend(['--mail-from={}'.format(msg_src)])
	if retrain:
		cmd.extend([ '--source=error',
			'--class={}'.format(_tag_ids[tag][1]),
			'--signature={}'.format(retrain) ])
	cmd_str = ' '.join(cmd)

	proc = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)
	with open(msg_path) as src: shutil.copyfileobj(src, proc.stdin)
	proc.stdin.close()
	summary = proc.stdout.read().strip()
	proc = proc.wait()
	if proc:
		raise DSpamError(( 'dspamc command ({}) returned'
			' error code ({}), message: {}' ).format(cmd_str, proc, msg_path))
	if retrain:
		log.debug('Retrain output (tag: {}): {!r}'.format(tag, summary))
		return
	log.debug('msg: %s, expect: %s, summary: %s', msg_path, tag, summary)

	res_error = lambda msg: DSpamError(
		'dspamc summary - {} ({!r}), message: {}'.format(msg, summary, msg_path) )
	if not summary.startswith('X-DSPAM-Result: '): raise res_error('format error')

	name, val = summary.split(':', 1)
	msg_class = re.search(r'\bclass="([^\s"]+)"', val)
	if not msg_class: raise res_error('missing class')
	msg_class = msg_class.group(1)

	if msg_class in _tag_ids[tag][0]: return

	if train:
		msg_sig = re.search(r'\bsignature=(\S+)', val)
		if not msg_sig: raise res_error('missing class')
		msg_sig = msg_sig.group(1)
		dspamc(msg_path, tag, user=user, retrain=msg_sig)
	return val.strip()


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Generate mail index file for dspam_train'
				' or optionally train dspam (via dspamc) on these,'
			' picking mails for it according to some specified criterias.')

	parser.add_argument('maildir',
		help='Path to maildir (maildir++'
			' mail storage format, not just any directory) to pick mails from.')
	parser.add_argument('index_file', nargs='?',
		help='Path to generated index file. Will be overwritten, if already exists.'
			' If not specified, file with unique name will be generated in TMPDIR'
				' and its path printed to stdout, unless --train/--test options are specified.')

	parser.add_argument('--train', action='store_true',
		help='Pass generated index entries to dspamc for training. Does not generate index file.')
	parser.add_argument('--test', action='store_true',
		help='Test if dspam misclassifies any entries in the index.'
			' Any mismatch will be reported. Does not generate index file.')
	parser.add_argument('-u', '--user',
		metavar='name', default='dspam',
		help='--user parameter to pass argument'
				' to dspam client (default: %(default)s), used for --test or --train options.'
			' dspam-recognized group names can be passed here as well.'
			' Affects spam classification groups and permissions. Empty - dont pass.')

	parser.add_argument('-s', '--spam-folder', action='append', default=list(),
		help='Folder where genuine spam mails end up.'
			' Paths can be specified as absolute or relative'
				' fs paths (e.g. "/reports/cron", "Sent", "lists/crypto/")'
				' or proper (dot-separated) maildir subdir names ("reports.cron", "Sent", "lists.crypto").'
			' Root (INBOX) path can be specified'
				' as an empty string (""), single dot (".") or slash ("/").'
			' Can be specified multiple times. Any missing path(s) will raise errors.')
	parser.add_argument('-r', '--ham-folder', action='append', default=list(),
		help='Folder where generic non-spam (desirable) messages are stored.'
			' Same notes on paths as for --spam-folder apply. Can be specified multiple times.')

	parser.add_argument('-t', '--ts-max', default='5d', metavar='ts_spec',
		help='How old (at least) message has'
				' to be to include it in the index (default: %(default)s).'
			' Empty value or "-" can be specified disable check.'
			' ts_spec can be short relative string like "12h", "3mo", "1y"'
				' or whatever "date" command or "dateutil" module (if present in system) can parse.'
			' Timestamp from message mtime is used, which should not change in general,'
				' see http://wiki2.dovecot.org/MailboxFormat/Maildir#Usage_of_timestamps.')
	parser.add_argument('--ts-min', default='6mo', metavar='ts_spec',
		help='Dont include messages older than specified date (default: %(default)s).'
			' Can generally be used to avoid feeding'
				' too much data (i.e. mails for last 20 years) to dspam.'
			' Same comments as for --ts-max apply.')
	parser.add_argument('--size-max', type=float, default=3, metavar='MiB',
		help='Dont include messages larger than the specified size'
			' (float, in MiB, default: %(default)s MiB). Negative value or 0 - disable check.')
	parser.add_argument('--ignore-flags', action='store_true',
		help='By default, only "Seen" (and flagged as such)'
			' messages are included in the index, this option disables that check.')

	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')

	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	if not opts.spam_folder:
		parser.error('At least one --spam-folder must be specified.')
	if not opts.ham_folder:
		parser.error('At least one --ham-folder must be specified.')

	global log
	import logging
	logging.basicConfig(level=logging.DEBUG if opts.debug else logging.WARNING)
	log = logging.getLogger()

	box = mailbox.Maildir(opts.maildir)
	ts_min, ts_max = it.imap(parse_timestamp, [opts.ts_min, opts.ts_max])
	size_max = opts.size_max * 2**20 if opts.size_max > 0 else None
	log.debug('Processing date range: %s - %s', ts_min, ts_max)

	corpus = dict(spam=set(), ham=set()) if opts.test or opts.train else None
	index = ( open(opts.index_file, 'w') if opts.index_file\
			else tempfile.NamedTemporaryFile(delete=False) )\
		if not corpus else None
	folders = list(('spam', p) for p in opts.spam_folder)\
		+ list(('ham', p) for p in opts.ham_folder)

	for tag, path in folders:
		for msg_path in path_process(
				box_path(box, path), seen_only=not opts.ignore_flags,
				ts_min=ts_min, ts_max=ts_max, size_max=size_max ):
			if index: index.write('{} {}\n'.format(tag, msg_path))
			if corpus: corpus[tag].add(msg_path)

	if index:
		index.close()
		if not opts.index_file: print(index.name)

	if corpus:
		log.debug('Processing corpus: %s ham, %s spam', len(corpus['ham']), len(corpus['spam']))

		def key_balancer():
			'Tries to spread "spam" msgs evenly over "ham" and vice-versa.'
			switch, keys = False, ['ham', 'spam']
			while True:
				yield keys[switch]
				others = len(corpus[keys[not switch]])
				if others == 0: continue
				# How many more messages of this type to throw in, if there's more of them
				balance = int(round(max(len(corpus[keys[switch]]) / others, 0), 0))
				for i in xrange(balance): yield keys[switch]
				switch = not switch

		keys = key_balancer()
		while any(corpus.values()):
			tag = next(keys)
			msg_path = corpus[tag].pop()
			try: mismatch = dspamc(msg_path, tag, train=opts.train, user=opts.user)
			except DSpamError as err:
				log.error(err.message)
				continue
			if mismatch and opts.test:
				print('Mismatch (expected: {}, path: {}): {}'.format(tag, msg_path, mismatch))


if __name__ == '__main__': sys.exit(main())
