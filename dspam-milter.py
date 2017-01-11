#!/usr/bin/env python2
# -*- coding: utf-8 -*-

# pymilter project - http://www.bmsi.com/python/milter.html
import Milter

import itertools as it, operator as op, functools as ft
from subprocess import Popen, PIPE
import os, sys, re, logging, signal, time


class MilterLogFilter(logging.Filter):

	milter_id_format = '{:04d}'
	msg_format_default = '{} :: {}'
	_msg_format_default = object()

	@classmethod
	def getLogger(cls, milter_id, ext='core', msg_format=_msg_format_default):
		milter_id = cls.milter_id_format.format(milter_id)
		assert milter_id
		log = logging.getLogger('dspam_milter.{}.{}'.format(ext, milter_id))
		log.addFilter(cls(milter_id, msg_format))
		return log

	def __init__(self, milter_id, msg_format=_msg_format_default):
		self.milter_id, self.msg_format = milter_id, msg_format\
			if msg_format is not self._msg_format_default else self.msg_format_default

	def filter(self, record):
		if getattr(record, 'milter_id', None) is None:
			record.milter_id = self.milter_id
			if self.msg_format:
				record.msg = self.msg_format\
					.format(self.milter_id, record.msg)
		return True


class MilterDspam(Milter.Base):

	dspamc_proc_wait = 0.5 # seconds to wait for dspamc to exit
	dspamc_proc_wait_checks = 8
	dspamc_proc_timeout = 5 * 60 # terminate dspamc pid after 5min
	dspamc_proc_timeout_kill = 20 # seconds before sending kill signal if pid fails to terminate

	def __init__(self, user, fail_pass=False, dspamc_opts=None):
		self.user, self.dspamc_opts = user, dspamc_opts or list()
		self.fail_action = Milter.TEMPFAIL if not fail_pass else Milter.ACCEPT
		self.state = 'ready' # ready, busy
		self.dspamc_procs = dict()
		self._log = MilterLogFilter.getLogger(Milter.uniqueID())

	def dspamc_proc_gc(self, new_proc=None):
		ts = time.time()
		if new_proc:
			self.dspamc_procs[new_proc.pid] = new_proc, ts
		for pid, (proc, proc_ts) in self.dspamc_procs.items():
			if proc.poll() is not None:
				err = proc.wait()
				if err: self._log.error('dspamc gc-ed process (pid: %s) returned error code: %s', pid, err)
				del self.dspamc_procs[pid]
			elif ts - proc_ts > self.dspamc_proc_timeout:
				self._log.warn('dspamc gc-ed process (pid: %s) timed-out, terminating', pid)
				proc.terminate()
				checks = (int(self.dspamc_proc_timeout_kill) + 1) / 5.0
				for n in xrange(checks):
					err = proc.poll()
					if err is not None or checks <= 0:
						if err is not None: err = proc.wait()
						break
					time.sleep(self.dspamc_proc_timeout_kill / checks)
				else: proc.kill()
				del self.dspamc_procs[pid]


	### Connections

	def _new_message(self):
		self.msg_headers, self.msg = list(), list()
		self.src, self.rcpts = None, set()
		self.state = 'busy'

	@Milter.noreply
	def connect(self, hostname, family, hostaddr):
		self._log.debug( 'Got connection to'
			' %s (from: %s [%s])', hostname, hostaddr, family )
		assert self.state == 'ready', self.state
		self._new_message()
		return Milter.CONTINUE

	def close(self):
		assert self.state == 'busy', self.state
		self._log.debug('Connecton closed')
		self.state = 'ready'
		return Milter.CONTINUE


	### Message buffering

	@staticmethod
	def _addr_filter(addr):
		addr = addr.strip()
		match = re.search(r'^<(.*)>$', addr)
		return match.group(1) if match else addr

	@Milter.noreply
	def envfrom(self, addr, *params):
		self.src = self._addr_filter(addr)
		self._log.debug('Got FROM: %r %r', self.src, params)
		return Milter.CONTINUE

	@Milter.noreply
	def envrcpt(self, addr, *params):
		rcpt = self._addr_filter(addr)
		self.rcpts.add(rcpt)
		self._log.debug('Got RCPT: %r %r', rcpt, params)
		return Milter.CONTINUE

	@Milter.noreply
	def header(self, name, val):
		self.msg_headers.append((name, val))
		self._log.debug('Got header: %r = %r', name, val)
		return Milter.CONTINUE

	@Milter.noreply
	def body(self, chunk):
		self.msg.append(chunk)
		self._log.debug('Got message body chunk (%s B)', len(chunk))
		return Milter.CONTINUE


	### Message handling

	def eom(self):
		msg = ''.join([
			''.join('{}: {}\r\n'.format(k, v) for k, v in self.msg_headers),
			'\r\n', ''.join(self.msg) ])
		msg_src, msg_dst = self.src, self.rcpts
		self._new_message()

		cmd = ['dspamc', '--deliver=summary']
		if self.user: cmd.extend(['--user', self.user])
		if msg_dst: cmd.extend(['--rcpt-to', ' '.join(sorted(msg_dst))])
		if msg_src: cmd.extend(['--mail-from={}'.format(msg_src)])
		cmd += self.dspamc_opts
		cmd_str = ' '.join(cmd)
		self._log.debug( 'Processing message'
			' (%s, %s B): %s', self.getsymval('i'), len(msg), cmd_str )

		try: proc = Popen(cmd, stdin=PIPE, stdout=PIPE, close_fds=True)
		except:
			self._log.exception('Failed to start dspamc: %s', cmd_str)
			return self.fail_action
		proc.stdin.write(msg)
		proc.stdin.close()

		proc_terminated = False
		summary = proc.stdout.readline().strip()

		if summary == '250 2.6.0 <dspam> Message accepted for delivery: INNOCENT':
			# Special case - happens when dspam gets huge message, dspamc hangs afterwards
			self._log.debug( 'dspamc special-case: huge message'
				' skip with "innocent" (src: %r, dst: %r)', msg_src, msg_dst )
			summary = ( 'X-DSPAM-Result: dspam; result="Innocent";'
				' class="Whitelisted"; probability=0.0000; confidence=1.00; signature=xxx' )
			proc.terminate()
			proc_terminated = True

		for n in xrange(self.dspamc_proc_wait_checks):
			err = proc.poll()
			if err is not None or self.dspamc_proc_wait_checks <= 0:
				if err is not None: err = proc.wait() if not proc_terminated else 0
				break
			time.sleep(self.dspamc_proc_wait / float(self.dspamc_proc_wait_checks))
		if err:
			self._log.error('dspamc process returned error code: %s', err)
			return self.fail_action
		else:
			self._log.debug( 'dspamc pid exit timed-out (with'
				' summary: %r), handing it off to dspamc_proc_gc: %s', summary, proc.pid )
			self.dspamc_proc_gc(proc)

		if not summary.startswith('X-DSPAM-Result: '):
			self._log.error('dspamc summary format error: %r', summary)
			return self.fail_action

		self._log.debug('dspamc summary: %s', summary)
		name, val = summary.split(':', 1)
		self.addheader(name.strip(), val.strip(), 0)
		return Milter.ACCEPT


def main(args=None):
	import argparse
	parser = argparse.ArgumentParser(
		description='Ad-hoc dspam milter that does --deliver=summary'
			' and only adds result as header, never rejecting or dropping messages.' )
	parser.add_argument('socket',
		nargs='?', default='local:/tmp/dspam_milter.sock',
		help='libmilter-format socket spec to listen on (default: %(default)s).'
			' Examples: local:/tmp/dspam_milter.sock, inet:1234@localhost, inet6:1234@localhost')
	parser.add_argument('-u', '--user',
		metavar='name', default='dspam',
		help='--user parameter to pass argument to dspam client (default: %(default)s).'
			' dspam-recognized group names can be passed here as well.'
			' Affects spam classification groups and permissions. Empty - dont pass.')
	parser.add_argument('-t', '--timeout',
		type=float, default=600, metavar='seconds',
		help='Number of seconds the MTA should wait'
			' for a response before considering this milter dead (default: %(default)s).')
	parser.add_argument('--dspam-fail-pass', action='store_true',
		help='Accept mails instead of returning TEMPFAIL'
			' if dspamc returns any kind of errors instead of filtering results.')
	parser.add_argument('--dspam-opts', action='append', metavar='options',
		help='Extra options to pass to dspamc command.'
			' Will be split on spaces, unless option is used multiple times.')
	parser.add_argument('--debug', action='store_true', help='Verbose operation mode.')
	opts = parser.parse_args(sys.argv[1:] if args is None else args)

	logging.basicConfig(
		level=logging.DEBUG if opts.debug else logging.WARNING,
		format='%(levelname)s :: %(message)s')
	log = logging.getLogger('dspam_milter.main')

	# pymilter uses stdout for spam, no logging should go there anyway
	sys.stdout = open(os.devnull, 'w')

	dspamc_opts = opts.dspam_opts or list()
	if len(dspamc_opts) == 1: dspamc_opts = dspamc_opts[0].strip().split()

	Milter.factory = ft.partial( MilterDspam, opts.user,
		fail_pass=opts.dspam_fail_pass, dspamc_opts=dspamc_opts )
	log.debug('Starting libmilter loop...')
	Milter.runmilter('DspamMilter', opts.socket, opts.timeout)
	log.debug('libmilter loop stopped')

if __name__ == '__main__': sys.exit(main())
