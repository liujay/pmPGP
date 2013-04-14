# -*- coding: UTF-8 -*-
"""
    gpgMime --- Utilities for sending/receiving PGP email messages
    built upon (1) GnuPG using gnupg for python and (2) codes from
    pgp-mime by W. T. King

 gpgMime is distributed in the hope that it will be useful, but WITHOUT ANY
 WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 A PARTICULAR PURPOSE.

    Jay S. Liu
    jay.s.liu@gmail.com
    Version 0.1
    Apr. 13, 2013
"""

"""
There is an issue (#14984) entitled:
``email.generator should always add newlines after closing boundaries``
for python versions: Python 3.3, Python 3.2, Python 2.7

***** You SHOULD resolve issue14983 on your python
        in order to make gpgMime work for you. *****

Detailed information regarding issue14983 can be obtained from:
http://bugs.python.org/issue14983


a diff file for python 2.7.3 generator.py is as follows:

----------------------------------------------------
@@ -227,9 +227,8 @@
             # body-part
             self._fp.write(body_part)
         # close-delimiter transport-padding
-        self._fp.write('\n--' + boundary + '--')
+        self._fp.write('\n--' + boundary + '--\n')
         if msg.epilogue is not None:
-            print >> self._fp
             self._fp.write(msg.epilogue)

     def _handle_multipart_signed(self, msg):
----------------------------------------------------

Documented by: Jay S. Liu
               Apr. 1, 2013

"""

# Copyright (C) 2012 W. Trevor King <wking@tremily.us>
#
# This file is part of pgp-mime.
#
# pgp-mime is free software: you can redistribute it and/or modify it under the
# terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# pgp-mime is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along with
# pgp-mime.  If not, see <http://www.gnu.org/licenses/>.

import os, copy, email
import tempfile, cStringIO
from email.mime.application import MIMEApplication as _MIMEApplication
from email.mime.multipart import MIMEMultipart as _MIMEMultipart
from email.encoders import encode_7or8bit as _encode_7or8bit
from email.generator import Generator

__version__ = '0.1.4'

def _flatten(message):
    fp = cStringIO.StringIO()
    g = Generator(fp, mangle_from_=False)
    g.flatten(message)
    return fp.getvalue()


def sign(message, gpg, **kwargs):
    r"""Sign a ``Message``, returning the signed version.

    using gpg.sign()
    others, mostly, taken from W. T. King
    """
    # should use replace, otherwise it does NOT work
    #   READ ---- page 5 of RFC 3156
    flattenedMsg = _flatten(message).replace('\n', '\r\n')
    assert kwargs
    signature = str( gpg.sign(flattenedMsg, detach=True, **kwargs) )
    assert signature
    sig = _MIMEApplication(
        _data=signature,
        _subtype='pgp-signature; name="signature.asc"',
        _encoder=_encode_7or8bit)
    sig['Content-Description'] = 'OpenPGP digital signature'
    sig.set_charset('us-ascii')

    msg = _MIMEMultipart(
        'signed', micalg='pgp-sha1', protocol='application/pgp-signature')
    msg.attach(message)
    msg.attach(sig)
    msg['Content-Disposition'] = 'inline'
    return msg

def encrypt(message, recipients, gpg, **kwargs):
    r"""Encrypt a ``Message``, returning the encrypted version.

    using gpg.encrypt()
    others, mostly, taken from W. T. King    
    """
    flattenedMsg = _flatten(message)
    eResult = gpg.encrypt(flattenedMsg, recipients, **kwargs)
    assert eResult.ok == True, (recipients, kwargs)
    encrypted = eResult.data
    enc = _MIMEApplication(
        _data=encrypted,
        _subtype='octet-stream; name="encrypted.asc"',
        _encoder=_encode_7or8bit)
    enc['Content-Description'] = 'OpenPGP encrypted message'
    enc.set_charset('us-ascii')
    control = _MIMEApplication(
        _data='Version: 1\n',
        _subtype='pgp-encrypted',
        _encoder=_encode_7or8bit)
    control.set_charset('us-ascii')
    msg = _MIMEMultipart(
        'encrypted',
        micalg='pgp-sha1',
        protocol='application/pgp-encrypted')
    msg.attach(control)
    msg.attach(enc)
    msg['Content-Disposition'] = 'inline'
    return msg

def sign_and_encrypt(message, recipients, gpg, **kwargs):
    r"""Sign and encrypt a ``Message``, returning the encrypted version.
    """
    signd = sign(message, gpg, **kwargs)
    msg = encrypt(signd, recipients, gpg)
    return msg


def _get_encrypted_parts(message):
    r"""Get the control and body part from the MIMEMultipart message

    taken from W. T. King
    """
    ct = message.get_content_type()
    assert ct == 'multipart/encrypted', ct
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-encrypted', params
    assert message.is_multipart(), message
    control = body = None
    for part in message.get_payload():
        if part == message:
            continue
        assert part.is_multipart() == False, part
        ct = part.get_content_type()
        if ct == 'application/pgp-encrypted':
            if control:
                raise ValueError('multiple application/pgp-encrypted parts')
            control = part
        elif ct == 'application/octet-stream':
            if body:
                raise ValueError('multiple application/octet-stream parts')
            body = part
        else:
            raise ValueError('unnecessary {} part'.format(ct))
    if not control:
        raise ValueError('missing application/pgp-encrypted part')
    if not body:
        raise ValueError('missing application/octet-stream part')
    return (control, body)

def _get_signed_parts(message):
    r"""Get the signature and body part from the MIMEMultipart message

    taken from W. T. King
    """
    ct = message.get_content_type()
    assert ct == 'multipart/signed', ct
    params = dict(message.get_params())
    assert params.get('protocol', None) == 'application/pgp-signature', params
    assert message.is_multipart(), message
    body = signature = None
    for part in message.get_payload():
        if part == message:
            continue
        ct = part.get_content_type()
        if ct == 'application/pgp-signature':
            if signature:
                raise ValueError('multiple application/pgp-signature parts')
            signature = part
        else:
            if body:
                raise ValueError('multiple non-signature parts')
            body = part
    if not body:
        raise ValueError('missing body part')
    if not signature:
        raise ValueError('missing application/pgp-signature part')
    return (body, signature)

def decrypt(message, gpg, **kwargs):
    r"""Decrypt a multipart/encrypted message

    using gpg.decrypt()
    others, mostly, taken from W. T. King
    """
    control, body = _get_encrypted_parts(message)
    encrypted = body.get_payload(decode=True)
    if not isinstance(encrypted, bytes):
        encrypted = encrypted.encode('us-ascii')
    result = gpg.decrypt(encrypted, **kwargs)
    assert result.ok == True, result
    return email.message_from_string(result.data)

def verify(message, gpg, **kwargs):
    r"""Verify a signature on ``message``, possibly decrypting first

    using gpg.verify_file() together with 
        cStringIO.StringIO() to hold the signature, and 
        tempfile.NamedTemporaryFile() to hold the message to be verified
    others, mostly, taken from W. T. King
    """
    ct = message.get_content_type()
    if ct == 'multipart/encrypted':             # decrypt first
        control, body = _get_encrypted_parts(message)
        encrypted = body.get_payload(decode=True)
        if not isinstance(encrypted, bytes):
            encrypted = encrypted.encode('us-ascii')
        result = gpg.decrypt(encrypted, **kwargs)   # result.data in string
        assert result.ok == True, result
        message = email.message_from_string(result.data) # string --> MIME message
    body, signature = _get_signed_parts(message)
    sig_data = signature.get_payload(decode=True)
    if not isinstance(sig_data, bytes):
        sig_data = sig_data.encode('us-ascii')
    #
    #   to use gpg.verify_file(stream, path_to_file) we need some efforts
    #       1. convert signature (sig_data) to a stream, and
    #       2. save body to a tempfile
    #
    #
    sig_stream = cStringIO.StringIO(sig_data)  # 1. convert signature to a stream
    fBody = _flatten(body).replace('\n', '\r\n')
    tmpFile = tempfile.NamedTemporaryFile()    # 2. save (replaced)body to a tempfile
    tmpFile.write(fBody)
    tmpFile.flush()
    verified = gpg.verify_file(sig_stream, tmpFile.name)
    assert verified.valid == True, verified
    return (copy.deepcopy(body), verified)

