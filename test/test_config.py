# Copyright (C) 2013  Red Hat
# see file 'COPYING' for use and warranty information
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.    See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#

import os
import re
import ssl
import time
import string
import requests
import socket
import subprocess
import test_util
import test_request

# Utility functions to assist in creating Apache configuration based
# on test suite

DEF_PORT=8000
FQDN = socket.gethostname()

default_vars = dict(
    DBPREFIX = '',
    SERVER_PORT = DEF_PORT,
    SERVER_NAME = FQDN,
    TEST_ROOT = '%s/work/httpd' % os.getcwd(),
    SERVER_ROOT = '%s/work/httpd' % os.getcwd(),
)

def template_str(txt, vars):
    val = string.Template(txt).substitute(vars)

    # eval() is a special string one can insert into a template to have the
    # Python interpreter evaluate the string. This is intended to allow
    # math to be performed in templates.
    pattern = re.compile('(eval\s*\(([^()]*)\))')
    val = pattern.sub(lambda x: str(eval(x.group(2))), val)

    return val

def template_file(infilename, vars):
    """Read a file and perform template substitutions"""
    with open(infilename) as f:
        return template_str(f.read(), vars)

def write_template_file(infilename, outfilename, vars):
    """Read a file and perform template substitutions"""
    replacevars = dict(default_vars.items() + vars.items())
    with open(outfilename, 'w') as f:
        f.write('%s\n' % template_file(infilename, replacevars))

def stop_apache():
    """Stop the Apache process"""
    cwd = os.getcwd()
    # no try/except, just let it fail
    os.chdir('work/httpd')

    p = subprocess.Popen(['./stop'],
                         close_fds=True)

def restart_apache():
    """Restart the Apache process"""
    cwd = os.getcwd()
    # no try/except, just let it fail
    os.chdir('work/httpd')

    p = subprocess.Popen(['./stop'],
                         close_fds=True)
    time.sleep(5)
    p = subprocess.Popen(['./start'],
                         close_fds=True)
    os.chdir(cwd)
    test_util.wait_for_open_ports(FQDN, DEF_PORT)

EXPECTED = """Expected %r to raise %s.
  options = %r
  output = %r"""

UNEXPECTED = """Expected %r to raise %s, but caught different.
  options = %r
  %s: %s"""

class Declarative(object):
    """A declarative-style test suite

    A Declarative test suite is controlled by the ``tests``
    class variable.

    The ``tests`` is a list of dictionaries with the following keys:

    ``desc``
        A name/description of the test
    ``request``
        A (uri, options) triple specifying the uri to run
    ``expected``
        Can be either an ``errors.PublicError`` instance, in which case
        the command must fail with the given error; or the
        expected result.
        The result is checked with ``tests.util.assert_deepequal``.
    """

    tests = tuple()

    def test_generator(self):
        """
        Iterate through tests.

        nose reports each one as a separate test.
        """

        # Iterate through the tests:
        name = self.__class__.__name__
        for (i, test) in enumerate(self.tests):
            nice = '%s[%d]: %s: %s' % (
                name, i, test['request'][0], test.get('desc', '')
            )
            func = lambda: self.check(nice, **test)
            func.description = nice
            yield (func,)

    def make_request(self, uri, options):
        session = requests.Session()
        session.mount('https://', test_request.MyAdapter())
        verify = dict(verify = options)
        port = options.get('port', DEF_PORT)
        host = options.get('host', FQDN)
        request = session.get('https://%s:%d%s' % (host, port, uri), **verify)

        return request

    def check(self, nice, desc, request, expected, cipher=None, protocol=None,
              expected_str=None, content=None):
        # TODO: need way to set auth, etc.
        (uri, options) = request
        if not 'verify' in options:
            options['verify'] = 'work/httpd/alias/ca.pem'
        if isinstance(expected, Exception):
            self.check_exception(nice, uri, options, expected, expected_str)
        else:
            self.check_result(nice, uri, options, expected, cipher, protocol,
                              content)

    def check_exception(self, nice, uri, options, expected, expected_str):
        """
        With some requests we expect an exception to be raised. See if
        is the one we expect. There is at least one case where depending
        on the distro either a CertificateError or an SSLError is
        thrown but the message of the exception is the same, so compare
        that.
        """
        klass = expected.__class__
        name = klass.__name__
        try:
            output = self.make_request(uri, options)
        except StandardError, e:
            pass
        else:
            raise AssertionError(
                EXPECTED % (uri, name, options, output)
            )
        if not isinstance(e, klass):
            if expected_str not in str(e):
                raise AssertionError(
                    UNEXPECTED % (uri, name, options, e.__class__.__name__, e)
                )

    def check_result(self, nice, uri, options, expected, cipher=None,
                     protocol=None, content=None):
        name = expected.__class__.__name__
        request = self.make_request(uri, options)
        has_sni = options.get('sni', False)

        if content and not content in request.content:
                raise AssertionError(
                    'Expected %s not in %s' % (content, request.content)
                )
        if cipher:
            if has_sni:
                raise AssertionError('Cannot do cipher tests in SNI')
            client_cipher = request.raw._pool._get_conn().client_cipher
            if cipher != client_cipher[0]:
                raise AssertionError(
                    'Expected cipher %s, got %s' % (cipher, client_cipher[0])
                )
        if protocol:
            client_cipher = request.raw._pool._get_conn().client_cipher
            if has_sni:
                raise AssertionError('Cannot do protocol tests in SNI')
            if protocol != client_cipher[1]:
                raise AssertionError(
                    'Expected protocol %s, got %s' % (protocol, client_cipher[1])
                )
        if expected != request.status_code:
                raise AssertionError(
                    'Expected status %s, got %s' % (expected, request.status_code)
                )
