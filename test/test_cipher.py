from test_config import Declarative
from test_util import run, assert_equal
import os
import nose
from nose.tools import make_decorator

# As of now there are 47 ciphers including ECC
WITH_ECC=47

cwd = os.getcwd()
srcdir = os.path.dirname(cwd)
exe = "%s/test_cipher" % srcdir

ciphernum = 0

class test_ciphers(object):
    @classmethod
    def setUpClass(cls):
        (out, err, rc) = run([exe, "--count"])
        assert rc == 0
        cls.ciphernum = int(out)

    def test_RC4(self):
        (out, err, rc) = run([exe, "RC4"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc4_56_sha')
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc4_56_sha, ecdh_ecdsa_rc4_128_sha, ecdhe_ecdsa_rc4_128_sha, ecdh_rsa_128_sha, ecdhe_rsa_rc4_128_sha, ecdh_anon_rc4_128sha')

    def test_AES(self):
        (out, err, rc) = run([exe, "AES"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_aes_128_sha, rsa_aes_256_sha, aes_128_sha_256, aes_256_sha_256, rsa_aes_128_gcm_sha_256')
        else:
            assert_equal(out, 'rsa_aes_128_sha, rsa_aes_256_sha, aes_128_sha_256, aes_256_sha_256, rsa_aes_128_gcm_sha_256, ecdh_ecdsa_rc4_128_sha, ecdh_ecdsa_3des_sha, ecdh_ecdsa_aes_128_sha, ecdh_ecdsa_aes_256_sha, ecdhe_ecdsa_rc4_128_sha, ecdhe_ecdsa_3des_sha, ecdhe_ecdsa_aes_128_sha, ecdhe_ecdsa_aes_256_sha, ecdh_rsa_128_sha, ecdh_rsa_3des_sha, ecdh_rsa_aes_128_sha, ecdh_rsa_aes_256_sha, ecdhe_rsa_aes_128_sha, ecdhe_rsa_aes_256_sha, ecdh_anon_aes_128_sha, ecdh_anon_aes_256_sha, ecdhe_ecdsa_aes_128_sha_256, ecdhe_rsa_aes_128_sha_256, ecdhe_ecdsa_aes_128_gcm_sha_256, ecdhe_rsa_aes_128_gcm_sha_256')


    def test_ALL(self):
        (out, err, rc) = run([exe, "ALL"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, aes_128_sha_256, aes_256_sha_256, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, rsa_aes_128_gcm_sha_256'
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, aes_128_sha_256, aes_256_sha_256, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, rsa_aes_128_gcm_sha_256, fips_3des_sha, fips_des_sha, ecdh_ecdsa_rc4_128_sha, ecdh_ecdsa_3des_sha, ecdh_ecdsa_aes_128_sha, ecdh_ecdsa_aes_256_sha, ecdhe_ecdsa_rc4_128_sha, ecdhe_ecdsa_3des_sha, ecdhe_ecdsa_aes_128_sha, ecdhe_ecdsa_aes_256_sha, ecdh_rsa_128_sha, ecdh_rsa_3des_sha, ecdh_rsa_aes_128_sha, ecdh_rsa_aes_256_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdhe_rsa_aes_128_sha, ecdhe_rsa_aes_256_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha, ecdh_anon_aes_128_sha, ecdh_anon_aes_256_sha, ecdhe_ecdsa_aes_128_sha_256, ecdhe_rsa_aes_128_sha_256, ecdhe_ecdsa_aes_128_gcm_sha_256, ecdhe_rsa_aes_128_gcm_sha_256')

    def test_ALL_no_AES(self):
        (out, err, rc) = run([exe, "ALL:-AES"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha')
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha')

    def test_SSLv3(self):
        (out, err, rc) = run([exe, "SSLv3"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha')
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha, ecdh_ecdsa_rc4_128_sha, ecdh_ecdsa_3des_sha, ecdh_ecdsa_aes_128_sha, ecdh_ecdsa_aes_256_sha, ecdhe_ecdsa_rc4_128_sha, ecdhe_ecdsa_3des_sha, ecdhe_ecdsa_aes_128_sha, ecdhe_ecdsa_aes_256_sha, ecdh_rsa_128_sha, ecdh_rsa_3des_sha, ecdh_rsa_aes_128_sha, ecdh_rsa_aes_256_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdhe_rsa_aes_128_sha, ecdhe_rsa_aes_256_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha, ecdh_anon_aes_128_sha, ecdh_anon_aes_256_sha')

    def test_SSLv3_equals_TLSv1(self):
        (out, err, rc) = run([exe, "SSLv3"])
        (out2, err2, rc2) = run([exe, "TLSv1"])
        assert rc == 0
        assert rc2 == 0
        assert_equal(out, out2)

    def test_TLSv12(self):
        if self.ciphernum < WITH_ECC:
            raise nose.SkipTest('ECC disabled')
        (out, err, rc) = run([exe, "TLSv12"])
        assert rc == 0
        assert_equal(out, 'aes_128_sha_256, aes_256_sha_256, rsa_aes_128_gcm_sha_256, ecdhe_ecdsa_aes_128_sha_256, ecdhe_rsa_aes_128_sha_256, ecdhe_ecdsa_aes_128_gcm_sha_256, ecdhe_rsa_aes_128_gcm_sha_256')

    def test_NULL(self):
        (out, err, rc) = run([exe, "NULL"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_null_md5, rsa_null_sha, null_sha_256')
        else:
            assert_equal(out, 'rsa_null_md5, rsa_null_sha, null_sha_256, ecdh_ecdsa_null_sha, ecdhe_ecdsa_null_sha, ecdh_rsa_null_sha, ecdhe_rsa_null, ecdh_anon_null_sha')

    def test_nss_rsa_rc4_128(self):
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+rsa_rc4_128_sha"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_md5, rsa_rc4_128_sha')

    def test_openssl_cipher(self):
        (out, err, rc) = run([exe, "DES-CBC3-SHA"])
        assert rc == 0
        assert_equal(out, 'rsa_3des_sha')

    def test_openssl_cipherlist(self):
        (out, err, rc) = run([exe, "DES-CBC3-SHA:RC4-SHA"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_sha, rsa_3des_sha')

    def test_EXP(self):
        (out, err, rc) = run([exe, "EXP"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_40_md5, rsa_rc2_40_md5, rsa_des_56_sha, rsa_rc4_56_sha')

    def test_MD5(self):
        (out, err, rc) = run([exe, "MD5"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc2_40_md5')

    def test_SHA(self):
        (out, err, rc) = run([exe, "SHA"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_128_sha, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha')
        else:
            assert_equal(out, 'rsa_rc4_128_sha, rsa_des_sha, rsa_3des_sha, rsa_aes_128_sha, rsa_aes_256_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha, ecdh_ecdsa_rc4_128_sha, ecdh_ecdsa_3des_sha, ecdh_ecdsa_aes_128_sha, ecdh_ecdsa_aes_256_sha, ecdhe_ecdsa_rc4_128_sha, ecdhe_ecdsa_3des_sha, ecdhe_ecdsa_aes_128_sha, ecdhe_ecdsa_aes_256_sha, ecdh_rsa_128_sha, ecdh_rsa_3des_sha, ecdh_rsa_aes_128_sha, ecdh_rsa_aes_256_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdhe_rsa_aes_128_sha, ecdhe_rsa_aes_256_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha, ecdh_anon_aes_128_sha, ecdh_anon_aes_256_sha')

    def test_SHA256(self):
        (out, err, rc) = run([exe, "SHA256"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'aes_128_sha_256, aes_256_sha_256')
        else:
            assert_equal(out, 'aes_128_sha_256, aes_256_sha_256, ecdhe_ecdsa_aes_128_sha_256, ecdhe_rsa_aes_128_sha_256')

    def test_SHA_MD5_minus_AES(self):
        (out, err, rc) = run([exe, "SHA:MD5:-AES"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha')
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha')

    def test_SHA_MD5_not_AES_HIGH(self):
        (out, err, rc) = run([exe, "!AES:SHA:MD5"])
        assert rc == 0
        if self.ciphernum < WITH_ECC:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha')
        else:
            assert_equal(out, 'rsa_rc4_40_md5, rsa_rc4_128_md5, rsa_rc4_128_sha, rsa_rc2_40_md5, rsa_des_sha, rsa_3des_sha, camelia_128_sha, rsa_des_56_sha, rsa_rc4_56_sha, camelia_256_sha, fips_3des_sha, fips_des_sha, ecdhe_rsa_rc4_128_sha, ecdhe_rsa_3des_sha, ecdh_anon_rc4_128sha, ecdh_anon_3des_sha')

    def test_nss_subtraction(self):
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+rsa_rc4_128_sha,-rsa_rc4_128_md5"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_sha')

    # As long as at least one is valid, things are ok
    def test_nss_unknown(self):
        (out, err, rc) = run([exe, "+rsa_rc4_128_md5,+unknown"])
        assert rc == 0
        assert_equal(out, 'rsa_rc4_128_md5')

    def test_nss_single(self):
        (out, err, rc) = run([exe, "+aes_128_sha_256"])
        assert rc == 0
        assert_equal(out, 'aes_128_sha_256')

    def test_invalid_format(self):
        (out, err, rc) = run([exe, "none"])
        assert rc == 1
        assert_equal(err, 'nss_engine_cipher.c:291, invalid cipher string none. Format is +cipher1,-cipher2...Unable to parse cipher list')
