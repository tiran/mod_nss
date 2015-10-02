from test_config import Declarative, write_template_file, restart_apache
from test_config import stop_apache
import ssl
import requests.exceptions
import os

class test_suite1(Declarative):
    @classmethod
    def setUpClass(cls):
        write_template_file('suite1.tmpl', 'work/httpd/conf/test.conf',
            {'DBPREFIX': os.environ.get('DBPREFIX', ''),
             'SNI': 'on',
             'PRESERVEHOST': 'Off',
            }
        )
        for i in range(1,26):
            write_template_file('sni.tmpl', 'work/httpd/conf.d/sni%d.conf' % i,
                {'DBPREFIX': os.environ.get('DBPREFIX', ''),
                 'SNINAME': 'www%d.example.com' % i,
                 'SNINUM': i,
                }
            )
        restart_apache()

    @classmethod
    def tearDownClass(cls):
        stop_apache()

    tests = [

        dict(
            desc='Get this host',
            request=('/', {'sni': True}),
            expected=200,
            content='content',
        ),

        dict(
            desc='Get www1.example.com',
            request=('/', {'host': 'www1.example.com', 'sni': True}),
            expected=200,
            content='sni1',
        ),

        dict(
            desc='Get www2.example.com',
            request=('/', {'host': 'www2.example.com', 'sni': True}),
            expected=200,
            content='sni2',
        ),

        dict(
            desc='Get www4.example.com',
            request=('/', {'host': 'www4.example.com', 'sni': True}),
            expected=200,
            content='sni4',
        ),

        dict(
            desc='Get www6.example.com',
            request=('/', {'host': 'www6.example.com', 'sni': True}),
            expected=200,
            content='sni6',
        ),

        dict(
            desc='Get www1.example.com again',
            request=('/', {'host': 'www1.example.com', 'sni': True}),
            expected=200,
            content='sni1',
        ),

        dict(
            desc='Get non-existant page on www8.example.com',
            request=('/notfound', {'host': 'www8.example.com', 'sni': True}),
            expected=404,
        ),

        dict(
            desc='Client auth to www10.example.com, valid certificate',
            request=('/acl/aclS01.html', {
                      'host': 'www10.example.com', 'sni': True,
                      'key_file': 'work/httpd/alpha.key',
                      'cert_file': 'work/httpd/alpha.crt',}
            ),
            expected=200,
            content='sni10', 
        ),

        dict(
            desc='Get www25.example.com',
            request=('/', {'host': 'www25.example.com', 'sni': True}),
            expected=200,
            content='sni25',
        ),

        dict(
            desc='Non-existant www26.example.com',
            request=('/', {'host': 'www26.example.com', 'sni': True}),
            expected=requests.exceptions.ConnectionError(),
        ),

        dict(
            desc='Reverse proxy request when SNI is enabled',
            request=('/proxy/index.html', {'sni': True}),
            expected=200,
        ),

    ]
