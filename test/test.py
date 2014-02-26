from test_config import Declarative, write_template_file, restart_apache
from test_config import stop_apache
import requests.exceptions

class test_suite1(Declarative):
    @classmethod
    def setUpClass(cls):
        write_template_file('suite1.tmpl', 'work/httpd/conf/test.conf', {})
        restart_apache()

    @classmethod
    def tearDownClass(cls):
        stop_apache()

    tests = [

        dict(
            desc='Basic SSL connection',
            request=('/', {}),
            expected=200,
        ),

        dict(
            desc='Basic SSL connection, 404',
            request=('/notfound', {}),
            expected=404,
        ),

        dict(
            desc='SSL connection, fail to verify',
            request=('/', {'verify': True}),
            expected=requests.exceptions.SSLError(),
        ),

        dict(
            desc='SSL AES128-SHA cipher check',
            request=('/index.html', {}),
            expected=200,
            cipher='AES128-SHA',
        ),

        dict(
            desc='Default protocol check',
            request=('/', {}),
            expected=200,
            protocol='TLSv1/SSLv3',
        ),

        dict(
            desc='server-side RC4 cipher check',
            request=('/rc4_cipher/', {'ciphers': 'ALL'}),
            expected=200,
            cipher='RC4-MD5',
        ),

        dict(
            desc='client-side RC4 cipher check',
            request=('/', {'ciphers': 'RC4-MD5'}),
            expected=200,
            cipher='RC4-MD5',
        ),

        dict(
            desc='Basic client auth, no certificate',
            request=('/acl/aclS01.html', {}),
            expected=requests.exceptions.SSLError(),
        ),

        dict(
            desc='Basic client auth, valid certificate',
            request=('/acl/aclS01.html', {
                      'key_file': 'work/httpd/alpha.key',
                      'cert_file': 'work/httpd/alpha.crt',}
            ),
            expected=200,
        ),

        dict(
            desc='NSSRequire auth, no certificate',
            request=('/acl/aclS02.html', {}),
            expected=requests.exceptions.SSLError(),
        ),

        dict(
            desc='NSSRequire auth, valid certificate',
            request=('/acl/aclS02.html', {
                      'key_file': 'work/httpd/alpha.key',
                      'cert_file': 'work/httpd/alpha.crt',}
            ),
            expected=200,
        ),

        dict(
            desc='NSSRequire auth, not allowed certificate',
            request=('/acl/aclS02.html', {
                      'key_file': 'work/httpd/beta.key',
                      'cert_file': 'work/httpd/beta.crt',}
            ),
            expected=403,
        ),

        dict(
            desc='FakeBasicAuth, no certificate',
            request=('/acl/aclS03.html', {}),
            expected=requests.exceptions.SSLError(),
        ),

        dict(
            desc='FakeBasicAuth, valid certificate',
            request=('/acl/aclS03.html', {
                      'key_file': 'work/httpd/alpha.key',
                      'cert_file': 'work/httpd/alpha.crt',}
            ),
            expected=200,
        ),

        dict(
            desc='FakeBasicAuth, not allowed user',
            request=('/acl/aclS03.html', {
                      'key_file': 'work/httpd/beta.key',
                      'cert_file': 'work/httpd/beta.crt',}
            ),
            expected=401,
        ),

        dict(
            desc='Secret key size',
            request=('/secret-test.html', {}),
            expected=200,
        ),

        dict(
            desc='Impossible secret key size',
            request=('/secret-test-impossible.html', {}),
            expected=403,
        ),

    ]
