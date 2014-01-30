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

        Keyword arguments:
        length -- Size of random secret to generate (default 32 char)

        Returns:
        Random secret of specified size securely generated using the system's
        CSPRNG. This is /dev/urandom for *nix-based systems and CryptGenRandom
        for Windows-based systems.

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

        Keyword arguments:
        secret -- The shared secret used to generate the HOTP value. This secret
        should be 160 bits as per RFC 4226.
        counter -- The counter value used to generate the HOTP value. The counter
        must be 8 bytes long and synchronized between the client and server.
        length -- The length of the HOTP value to generate. (default 6)

        Returns:
        The generated HOTP value of the specified length.

        """
        secret = base64.b32decode(secret, casefold=True)
        HS = hmac.new(secret, struct.pack('>Q', counter), hashlib.sha1).digest()
        sbit = cls._dynamic_truncate(HS)
        return str(sbit % (10**length)).zfill(length)

    @classmethod
    def validate_hotp(cls, hotp, secret, counter, length=6, look_ahead=3):
        """Validates an HOTP value.

        Keyword arguments:
        hotp -- The HOTP value to be validated.
        secret -- The shared secret used to generate the HOTP value. This secret
        should be 160 bits as per RFC 4226.
        counter -- The counter value used to generate the HOTP value. The counter
        must be 8 bytes long and synchronized between the client and server.
        length -- The length of the HOTP value to generate. (default 6)
        look_ahead -- The look-ahead window for calculating the validity of the
        HOTP value. (default 3)

        Returns:
        True if the HOTP value is valid, False if the value is invalid.

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

        Keyword arguments:
        secret -- The shared secret used to generate the TOTP value. This secret
        should be 160 bits as per RFC 4226.
        time -- The time value used to generate the TOTP value. The time value is
        the current unix time expressed as an integer.
        length -- The length of the HOTP value to generate. (default 6)

        Returns:
        The generated TOTP value of the specified length.

        """
        totp = cls.generate_hotp(secret, int(math.floor(time/30)), length)
        return totp.zfill(length)

    @classmethod
    def validate_totp(cls, totp, secret, time, length=6):
        """Validates an TOTP value.

        Keyword arguments:
        totp -- The TOTP value to be validated.
        secret -- The shared secret used to generate the TOTP value. This secret
        should be 160 bits as per RFC 4226.
        time -- The time value used to generate the TOTP value. The time value is
        the current unix time expressed as an integer.
        length -- The length of the HOTP value to generate. (default 6)

        Returns:
        True if the TOTP value is valid, False if the value is invalid.

        """
        if cls.generate_totp(secret, time, length) == totp:
            return True

        else:
            return False

    @classmethod
    def _dynamic_truncate(cls, hmac_value):
        """Extracts a 4 byte binary value from a 20 byte HMAC-SHA1 result

        This function is described in RFC 4226 Section 5.3

        Keyword arguments:
        hmac_value -- The HMAC-SHA1 result to truncate

        Returns:
        The truncated 4 byte binary value.

        """
        offset_bits = ord(hmac_value[19]) & 0b1111
        offset = int(offset_bits)
        P = hmac_value[offset:offset+4]
        return struct.unpack('>I', P)[0] & 0x7fffffff

    @classmethod
    def _get_current_unix_time(cls):
        """Returns the current unix time as an integer."""
        return int(time.time())