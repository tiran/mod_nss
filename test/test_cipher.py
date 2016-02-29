from test_util import run, assert_equal
import os
import nose
from nose.tools import make_decorator

# This file is auto-generated by configure
from variable import ENABLE_SHA384, ENABLE_GCM, ENABLE_SERVER_DHE

cwd = os.getcwd()
srcdir = os.path.dirname(cwd)
exe = "%s/test_cipher" % srcdir
openssl = "/usr/bin/openssl"

ciphernum = 0

CIPHERS_NOT_IN_NSS = ['ECDH-RSA-AES128-SHA256',
                      'ECDH-ECDSA-AES128-GCM-SHA256',
                      'ECDH-ECDSA-AES128-SHA256',
                      'ECDH-RSA-AES128-GCM-SHA256',
                      'EXP-DES-CBC-SHA',
                      'ECDH-RSA-AES256-GCM-SHA384',
                      'ECDH-ECDSA-AES256-SHA384',
                      'ECDH-RSA-AES256-SHA384',
                      'ECDH-ECDSA-AES256-GCM-SHA384',
                      'EXP-EDH-RSA-DES-CBC-SHA',
]

OPENSSL_CIPHERS_IGNORE = ":-SSLv2:-KRB5:-PSK:-ADH:-DSS:-SEED:-IDEA"

if ENABLE_SERVER_DHE == 0:
    OPENSSL_CIPHERS_IGNORE += ':-DH'

def assert_equal_openssl(ciphers):
    nss_ciphers = ciphers
    ossl_ciphers = ciphers + OPENSSL_CIPHERS_IGNORE
    (nss, err, rc) = run([exe, "--o", nss_ciphers])
    assert rc == 0
    (ossl, err, rc) = run([openssl, "ciphers", ossl_ciphers])
    assert rc == 0

    nss_list = nss.strip().split(':')
    nss_list.sort()

    ossl_list = ossl.strip().split(':')
    ossl_list = list(set(ossl_list))
    ossl_list.sort()

    # NSS doesn't support the SHA-384 ciphers, remove them from the OpenSSL
    # output.
    t = list()
    for o in ossl_list:
        if not ENABLE_SHA384 and 'SHA384' in o:
            continue
        if not ENABLE_GCM and 'GCM' in o:
            continue
        if o.startswith('DH-'):
            continue
        if o in CIPHERS_NOT_IN_NSS:
            continue
        t.append(o)
    ossl_list = t

    if len(nss_list) > len(ossl_list):
        diff = set(nss_list) - set(ossl_list)
    elif len(ossl_list) > len(nss_list):
        diff = set(ossl_list) - set(nss_list)
    else:
        diff = ''

    assert nss_list == ossl_list, '%r != %r. Difference %r' % (':'.join(nss_list), ':'.join(ossl_list), diff)

def assert_no_NULL(nss_ciphers):
    (nss, err, rc) = run([exe, "--o", nss_ciphers])
    assert rc == 0
    assert('NULL' not in nss)

class test_ciphers(object):
    @classmethod
    def setUpClass(cls):
        (out, err, rc) = run([exe, "--count"])
        assert rc == 0
        cls.ciphernum = int(out)

    def test_RSA(self):
        assert_equal_openssl("RSA")

    def test_kRSA(self):
        assert_equal_openssl("kRSA")

    def test_aRSA(self):
        assert_equal_openssl("aRSA")

    def test_EDH(self):
        assert_equal_openssl("EDH")

    def test_DH(self):
        assert_equal_openssl("DH")

    def test_RC4(self):
        assert_equal_openssl("RC4")

    def test_RC2(self):
        assert_equal_openssl("RC2")

    def test_AES(self):
        assert_equal_openssl("AES")

    def test_AESGCM(self):
        assert_equal_openssl("AESGCM")

    def test_AES128(self):
        assert_equal_openssl("AES128")

    def test_AES256(self):
        assert_equal_openssl("AES256")

    def test_CAMELLIA(self):
        assert_equal_openssl("CAMELLIA")

    def test_CAMELLIA128(self):
        assert_equal_openssl("CAMELLIA128")

    def test_CAMELLIA256(self):
        assert_equal_openssl("CAMELLIA256")

    def test_3DES(self):
        assert_equal_openssl("3DES")

    def test_DES(self):
        assert_equal_openssl("DES")

    def test_ALL(self):
        assert_equal_openssl("ALL")

    def test_ALL_no_AES(self):
        assert_equal_openssl("ALL:-AES")

    def test_COMPLEMENTOFALL(self):
        assert_equal_openssl("COMPLEMENTOFALL")

    # skipping DEFAULT as we use the NSS defaults
    # skipping COMPLEMENTOFDEFAULT as these are all ADH ciphers

    def test_SSLv3(self):
        assert_equal_openssl("SSLv3")

    def test_SSLv3_equals_TLSv1(self):
        (nss, err, rc) = run([exe, "--o", "SSLv3"])
        (nss2, err, rc2) = run([exe, "--o", "TLSv1"])
        assert rc == 0
        assert rc2 == 0
        assert_equal(nss, nss2)

    def test_TLSv12(self):
        assert_equal_openssl("TLSv1.2")

    def test_NULL(self):
        assert_equal_openssl("NULL")

    def test_nss_rsa_rc4_128(self):
        # Test NSS cipher parsing
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+rsa_rc4_128_sha"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_md5, rsa_rc4_128_sha')

    def test_EXP(self):
        assert_equal_openssl("EXP")

    def test_EXPORT(self):
        assert_equal_openssl("EXPORT")

    def test_EXPORT40(self):
        assert_equal_openssl("EXPORT40")

    def test_MD5(self):
        assert_equal_openssl("MD5")

    def test_SHA(self):
        assert_equal_openssl("SHA")

    def test_HIGH(self):
        assert_equal_openssl("HIGH")

    def test_MEDIUM(self):
        assert_equal_openssl("MEDIUM")

    def test_LOW(self):
        assert_equal_openssl("LOW")

    def test_SHA256(self):
        assert_equal_openssl("SHA256")

    def test_SHA_MD5_minus_AES(self):
        assert_equal_openssl("SHA:MD5:-AES")

    def test_SHA_MD5_not_AES(self):
        assert_equal_openssl("!AES:SHA:MD5")

    def test_aECDH(self):
        assert_equal_openssl("aECDH")

    def test_kECDH(self):
        assert_equal_openssl("kECDH")

    def test_kECDHe(self):
        assert_equal_openssl("kECDHe")

    def test_kECDHr(self):
        assert_equal_openssl("kECDHr")

    def test_kEECDH(self):
        assert_equal_openssl("kEECDH")

    def test_AECDH(self):
        assert_equal_openssl("AECDH")

    def test_EECDH(self):
        assert_equal_openssl("EECDH")

    def test_ECDSA(self):
        assert_equal_openssl("ECDSA")

    def test_aECDSA(self):
        assert_equal_openssl("aECDSA")

    def test_ECDH(self):
        assert_equal_openssl("ECDH")

    def test_AES_no_ECDH(self):
        assert_equal_openssl("AES:-ECDH")

    def test_AES_plus_RSA(self):
        assert_equal_openssl("AES+RSA")

    def test_logical_and_3DES_RSA(self):
        assert_equal_openssl("3DES+RSA")

    def test_logical_and_RSA_RC4(self):
        assert_equal_openssl("RSA+RC4")

    def test_logical_and_ECDH_SHA(self):
        assert_equal_openssl("ECDH+SHA")

    def test_logical_and_RSA_RC4_no_SHA(self):
        assert_equal_openssl("RSA+RC4:!SHA")

    def test_additive_RSA_RC4(self):
        assert_equal_openssl("RSA:+RC4")

    def test_additive_ECDH_plus_aRSA(self):
        assert_equal_openssl("ECDH+aRSA")

    def test_negative_plus_RSA_MD5(self):
        assert_equal_openssl("-RC2:RSA+MD5")

    def test_DEFAULT_aRSA(self):
        assert_no_NULL("DEFAULT:aRSA")

    def test_nss_subtraction(self):
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+rsa_rc4_128_sha,-rsa_rc4_128_md5"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_sha')

    def test_openssl_cipher(self):
        (out, err, rc) = run([exe, "DES-CBC3-SHA"])
        assert rc == 0
        assert_equal(out, 'rsa_3des_sha')

    def test_openssl_cipherlist(self):
        (out, err, rc) = run([exe, "DES-CBC3-SHA:RC4-SHA"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_sha, rsa_3des_sha')

    # As long as at least one is valid, things are ok
    def test_nss_unknown(self):
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+unknown"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_md5')

    def test_nss_single(self):
        (out, err, rc) = run([exe, "+aes_128_sha_256"])
        assert rc == 0
        assert_equal(out, 'aes_128_sha_256')

    def test_openssl_single_cipher(self):
        assert_equal_openssl("RC4-SHA")

    def test_invalid_format(self):
        (out, err, rc) = run([exe, "none"])
        assert rc == 1
