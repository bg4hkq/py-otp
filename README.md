py-otp
==========

![](https://travis-ci.org/Ayrx/py-otp.png?branch=develop)

**Warning**: This library should no longer be used as it won't be updated or supported.
I strongly recommend using the HOTP and TOTP implementation in 
[cryptography](https://github.com/pyca/cryptography) I wrote instead. 

### Introduction

This library provides an implementation of the HOTP and TOTP algorithms compatible
with the Google Authenticator app as per RFC 4226 and 6238.

### Installation

```
sudo pip install py-otp
```

### Usage

```
from otp import OTP
```
Import the `OTP` class into your python source file. All functions in the `OTP`
class are exposed as `@classmethod`. 

Example usage to generate secret

```
from otp import OTP
secret = OTP.generate_secret()
```

Refer to `otp/test_OTP.py` for more usage examples.

### License

```
The MIT License (MIT)

Copyright (c) 2013 Terry Chia

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
```
