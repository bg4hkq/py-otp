import base64
from unittest import TestCase
from otp import OTP

__author__ = 'Terry Chia'


class TestOTP(TestCase):
    def setUp(self):
        self.secret = base64.b32encode('12345678901234567890')

    def test_generate_hotp(self):
        # Test vectors taken from RFC 4226, Appendix E

        self.assertEqual('755224', OTP.generate_hotp(self.secret, 0))
        self.assertEqual('287082', OTP.generate_hotp(self.secret, 1))
        self.assertEqual('359152', OTP.generate_hotp(self.secret, 2))
        self.assertEqual('969429', OTP.generate_hotp(self.secret, 3))
        self.assertEqual('338314', OTP.generate_hotp(self.secret, 4))
        self.assertEqual('254676', OTP.generate_hotp(self.secret, 5))
        self.assertEqual('287922', OTP.generate_hotp(self.secret, 6))
        self.assertEqual('162583', OTP.generate_hotp(self.secret, 7))
        self.assertEqual('399871', OTP.generate_hotp(self.secret, 8))
        self.assertEqual('520489', OTP.generate_hotp(self.secret, 9))

    def test_generate_totp(self):
        # Test vectors taken from RFC 6238, Appendix B

        self.assertEqual('94287082', OTP.generate_totp(self.secret, 59, 8))
        self.assertEqual('07081804', OTP.generate_totp(self.secret, 1111111109, 8))
        self.assertEqual('14050471', OTP.generate_totp(self.secret, 1111111111, 8))
        self.assertEqual('89005924', OTP.generate_totp(self.secret, 1234567890, 8))
        self.assertEqual('69279037', OTP.generate_totp(self.secret, 2000000000, 8))
        self.assertEqual('65353130', OTP.generate_totp(self.secret, 20000000000, 8))

    def test_validate_hotp(self):
        self.assertTrue(OTP.validate_hotp('755224', self.secret, 0))
        self.assertTrue(OTP.validate_hotp('287082', self.secret, 0))
        self.assertFalse(OTP.validate_hotp('969429', self.secret, 0))

    def test_validate_totp(self):
        self.assertTrue(OTP.validate_totp('07081804', self.secret, 1111111109, 8))
        self.assertTrue(OTP.validate_totp('07081804', self.secret, 1111111084, 8))
        self.assertFalse(OTP.validate_totp('07081804', self.secret, 1111111078, 8))
        self.assertFalse(OTP.validate_totp('07081804', self.secret, 1111111140, 8))