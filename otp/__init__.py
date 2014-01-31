import base64
import hashlib
import hmac
import random
import struct
import math
import time

__author__ = 'Terry Chia'


class OTP:

    @classmethod
    def generate_secret(cls, length=32):
        """Securely generates random secret using the system's CSPRNG.

        :param length: Size of random secret to generate.
        :type length: int

        :returns: Random secret of specified size securely generated
                  using the system's CSPRNG. This is /dev/urandom for
                  *nix-based systems and CryptGenRandom for
                  Windows-based systems.
        :rtype: str

        """
        rand = random.SystemRandom()
        chars = base64._b32alphabet.values()

        secret = ''

        for i in xrange(length):
            secret = secret + rand.choice(chars)

        return secret

    @classmethod
    def generate_hotp(cls, secret, counter, length=6):
        """Generates an HOTP value.

        :param secret: The shared secret used to generate the HOTP value.
        :type secret: str
        :param counter: The counter value used to generate the HOTP value.
        :type counter: int
        :param length: The length of the HOTP value to generate.
        :type length: int

        :returns: The generated HOTP value of the specified length.
        :rtype: str

        """
        secret = base64.b32decode(secret, casefold=True)
        HS = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
        sbit = cls._dynamic_truncate(HS)
        return str(sbit % (10**length)).zfill(length)

    @classmethod
    def validate_hotp(cls, hotp, secret, counter, length=6, look_ahead=3):
        """Validates an HOTP value.

        :param hotp: The HOTP value to be validated.
        :type hotp: str
        :param secret: The shared secret used to generate the HOTP value.
        :type secret: str
        :param counter: The counter value used to generate the HOTP value.
        :type counter: int
        :param length: The length of the HOTP value to generate.
        :type length: int
        :param look_ahead: The look-ahead window for calculating the validity
         of the HOTP value.
        :type look_ahead: int

        :returns: True if the HOTP value is valid, False if otherwise.
        :rtype: bool

        """
        validity = False

        for i in xrange(look_ahead):
            if cls.generate_hotp(secret, counter, length) == hotp:
                validity = True
                break
            else:
                counter += 1

        return validity

    @classmethod
    def generate_totp(cls, secret, time, length=6):
        """Generates an TOTP value.

        :param secret: The shared secret used to generate the TOTP value.
        :type secret: str
        :param time: The time value used to generate the TOTP value. The time
         value is the current unix time expressed as an integer.
        :type time: int
        :param length: The length of the TOTP value to generate.
        :type length: int

        :returns: The generated TOTP value of the specified length.
        :rtype: str

        """
        totp = cls.generate_hotp(secret, int(math.floor(time/30)), length)
        return totp.zfill(length)

    @classmethod
    def validate_totp(cls, totp, secret, time, length=6):
        """Validates an TOTP value.

        :param totp: The TOTP value to be validated.
        :type totp: str
        :param secret: The shared secret used to generate the TOTP value.
        :type secret: str
        :param time: The time value used to generate the TOTP value. The time
         value is the current unix time expressed as an integer.
        :type time: int
        :param length: The length of the TOTP value to generate.
        :type length: int

        :returns: True if the TOTP value is valid, False if otherwise.
        :rtype: bool

        """
        if cls.generate_totp(secret, time, length) == totp:
            return True

        else:
            return False

    @classmethod
    def _dynamic_truncate(cls, hmac_value):
        """Extracts a 4 byte binary value from a 20 byte HMAC-SHA1 result

        This function is described in RFC 4226 Section 5.3

        :param hmac_value: The HMAC-SHA1 result to truncate
        :type hmac_value: str

        :returns: The truncated 4 byte binary value.
        :rtype: int

        """
        offset_bits = ord(hmac_value[19]) & 0b1111
        offset = int(offset_bits)
        P = hmac_value[offset:offset+4]
        return struct.unpack('>I', P)[0] & 0x7fffffff

    @classmethod
    def _get_current_unix_time(cls):
        """Returns the current unix time as an integer."""
        return int(time.time())