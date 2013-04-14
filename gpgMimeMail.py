#!/usr/bin/python
# -*- coding: UTF-8 -*-
"""
    sendding PGP email in MIME format
    built upon: gpgMime 
    
    By: Jay S. Liu
        jay.s.liu@gmail.com
        Apr. 4, 2013
        Version 0.1.4
"""

import os, sys, smtplib
import gnupg
import mimetypes
import os.path
import zipfile, tempfile
from email import encoders
from email.mime.text import MIMEText as _MIMEText
from email.mime.audio import MIMEAudio
from email.mime.base import MIMEBase
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.parser import HeaderParser

def nonAsciiString(str):
    r"""A simple but not reliable check on encoding type of input string
    """
    return not all(ord(c) < 128 for c in str)

def myMIMEText(body, subtype=None, encoding='utf-8', filename=None):
    r"""Wrap ``MIMEText`` with proper ``encoding``
    only utf-8 or us-ascii are supported

    by default: all text files are encoded with utf-8 to avoid signature error
    if, however, you don't like this, risk yourself for us-ascii/utf-8
    """
    if ( encoding != 'utf-8' ):
        if nonAsciiString(body):
            encoding = 'utf-8'
        else:
            encoding = 'us-ascii'
    message = _MIMEText(body, subtype, encoding)
    message.add_header('Content-Disposition', 'inline', filename = filename)
    return message

def attach_root(header, root_part):
    r"""Copy headers from message ``header`` onto message ``root_part``,
    and return the newly formed message ``root_part``.

    This is equivalent to combine header and root_part into one message,
    i.e., root_part = header + root_part.
    """
    for k,v in header.items():
        root_part[k] = v
    return root_part

def load_attachment(filename, aka=None, encoding='utf-8'):
    r"""Read and wrap the ``filename`` into a proper MIME message
    """
    ctype, _encoding_ = mimetypes.guess_type(filename)
    if ctype:
        maintype, subtype = ctype.split('/', 1)
    else:               #   fail in guessing mime type
        maintype, subtype = 'application', 'octet-stream'
    if maintype == 'text':
        fp = open(filename)
        message = myMIMEText(fp.read(), subtype, encoding=encoding)
        del message['Content-Disposition']          # no inline for text attachment
        fp.close()
    elif maintype == 'image':
        fp = open(filename, 'rb')
        message = MIMEImage(fp.read(), _subtype=subtype)
        fp.close()
    elif maintype == 'audio':
        fp = open(filename, 'rb')
        message = MIMEAudio(fp.read(), _subtype=subtype)
        fp.close()
    else:
        fp = open(filename, 'rb')
        message = MIMEBase(maintype, subtype)
        message.set_payload(fp.read())
        fp.close()
        # Encode the payload using Base64
        encoders.encode_base64(message)
    if aka:                     # use aka instead of filename, if specified
        filename = aka
    message.add_header('Content-Disposition', 'attachment', filename=filename)
    return message

def zipdir(dirName, zfile, hide=True):
    r"""zip all files in directory ``dirName`` recursively, output in ``zfile``
    """
    if hasattr(zipfile,'ZIP_DEFLATED'):     # check for zipfile compression
        zf = zipfile.ZipFile(zfile, 'w', zipfile.ZIP_DEFLATED)
    else:
        zf = zipfile.ZipFile(zfile, 'w')
    basedir = os.path.dirname(dirName)
    fnOffset = len(basedir)+len(os.sep)     # offset for zfn
    for root, dirs, files in os.walk(dirName):
        if ( hide ):
            #skip hidden directories
            if os.path.basename(root)[0] == '.':
                continue
        for f in files:
            # no recursive on zfile itself
            if ( f == zfile ):
                continue            #skip zfile itself
            if ( hide ):
                # skip backup files and all hidden files except .htaccess
                if f[-1] == '~' or (f[0] == '.' and f != '.htaccess'):
                    continue
            absfn = os.path.join(root, f)   # absolute path name
            zfn = absfn[fnOffset:]          # take off offset --> relative path name
            zf.write(absfn, zfn)
    zf.close()

def header_from_text(text):
    r"""Parse and form message headers from ``text``
    """
    text = text.strip()
    p = HeaderParser()
    return p.parsestr(text, headersonly=True)

if __name__ == '__main__':
    import gpgMime
    import argparse

    doc_lines = __doc__.splitlines()
    parser = argparse.ArgumentParser(
        description = doc_lines[0],
        epilog = '\n'.join(doc_lines[1:]).strip(),
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        '-v', '--version', action='version',
        version='%(prog)s: Version {}'.format(gpgMime.__version__))
    parser.add_argument(
        '-H', '--header-file', metavar='FILE', required=True,
        help='file containing email header')
    parser.add_argument(
        '-B', '--body-file', metavar='FILE',
        help='file containing email body')
    parser.add_argument(
        '-a', '--attachment', metavar='FILE', nargs='+',
        help='add attachment(s) to your message')
    parser.add_argument(
        '-d', '--directory', metavar='DIRECTORY',
        help='add a directory to your message')
    parser.add_argument(
        '-m', '--mode', default='sign', metavar='MODE',
        choices=['sign', 'encrypt', 'sign-encrypt', 'plain', 'Sencrypt'],
        help='encryption mode')
    parser.add_argument(
        '-s', '--sign-as', metavar='KEY',
        help="gpg key to sign with (gpg's -u/--local-user)")
    parser.add_argument(
        '-S', '--subject', metavar='SUBJECT',
        help="subject of this email")
    parser.add_argument(
        '-p', '--passphrase', metavar='PASSPHRASE',
        help="gpg private key passphrase for signer\
        or passphrase for symmetric encryption")
    parser.add_argument(
        '--output', action='store_const', const=True,
        help="don't mail the generated message, print it to stdout instead")
    parser.add_argument(
        '-V', '--verbose', default=0, action='count',
        help='increment verbosity')
    parser.add_argument(
        '-e', '--encoding', metavar='ENCODING',
        choices=['utf-8', 'us-ascii'],
        help='encoding for text files')

    args = parser.parse_args()
    if args.verbose:
        print args

    #
    # prepare email header
    #   --> msgHeader
    #
    headerText = open(args.header_file, 'rb').read()
    msgHeader = header_from_text(headerText)
    fromAddr = msgHeader.get('from')
    assert fromAddr
    toAddrs = msgHeader.get('to')       # one recipient is allowed
    assert toAddrs
    #
    # prepare email body, if there is one in (text) file
    #
    if args.body_file:
        body_text = open(args.body_file, 'rb').read()
        _body = myMIMEText(body_text, subtype='plain', filename='MailBody.txt')
        body = _body        # just in case: no attachment and no directory
    #
    # prepare email attachments, if any
    #
    if args.attachment:
        body = MIMEMultipart()
        if args.body_file:
            body.attach(_body)
        for attachment in args.attachment:
            assert os.path.isfile(attachment) and os.path.exists(attachment), attachment
            body.attach(load_attachment(attachment))
    #
    # prepare a directory as an attachment, if any
    #
    if args.directory:
        # create multipart if (1) no `body` msg, or (2) only MailBody so far 
        if (not vars().has_key('body')) or (not isinstance(body, MIMEMultipart)):
            body = MIMEMultipart()
            if args.body_file:
                body.attach(_body)
        #
        # normalize path to absolute path
        #
        if ( args.directory[:1] == '~' ):
            _dir = os.path.expanduser(args.directory)
            _dir = os.path.realpath(_dir)           # take care of trailing /, if there
        else:
            _dir = os.path.realpath(args.directory)
        assert os.path.isdir(_dir) and os.path.exists(_dir), _dir
        _zipFile = tempfile.NamedTemporaryFile(delete=False)
        zipdir(_dir, _zipFile)
        _zname = os.path.basename(_dir) + '.zip'
        body.attach(load_attachment(_zipFile.name, aka=_zname))
        try:
            os.remove(_zipFile.name)
        except Exception as e:
            print e

    assert body

    #
    #   let gnupg work on email body
    #       --> msgBody
    #
    gpg = gnupg.GPG()
    kwds = {}
    if args.passphrase:
        kwds = {'passphrase':args.passphrase}
    if args.sign_as:
        kwds['keyid'] = args.sign_as
    else:
        kwds['keyid'] = fromAddr
    if args.mode == 'sign':
        assert 'passphrase' in kwds, kwds
        msgBody = gpgMime.sign(body, gpg, **kwds)
    elif args.mode == 'encrypt':
        msgBody = gpgMime.encrypt(body, toAddrs, gpg)
    elif args.mode == 'sign-encrypt':
        assert 'passphrase' in kwds, kwds
        msgBody = gpgMime.sign_and_encrypt(body, toAddrs, gpg, **kwds)
    elif args.mode == 'Sencrypt':
        #
        # only symmetric encryption is supported, NO signature
        #
        assert 'passphrase' in kwds, kwds
        kwds['symmetric'] = True
        #kwds['sign'] = None
        del kwds['keyid']
        msgBody = gpgMime.encrypt(body, None, gpg, **kwds)
    elif args.mode == 'plain':
        msgBody = body
    else:
        raise Exception('unrecognized mode {}'.format(args.mode))
    #
    #   combine email headers and body
    #
    msg = attach_root(msgHeader, msgBody)
    #
    #   some tricks on subject
    #
    if args.subject:
        try:                        # delete message subject if exists
            del msg['Subject']
        except KeyError:
            pass
        _subject = args.subject
    else:
        _subject = msg['Subject']
    _subject += ' ' + args.mode
    if args.directory:
        _subject += ' ' + args.directory
    if args.verbose:
        _subject += ' ' + str(os.getpid())
    msg['Subject'] = _subject

    #
    #   output or sending the message
    #       only smpt on localhost is supported in this version
    #           work for yourself if it does not fit you
    #
    if args.output:
        print(msg.as_string())
    else:
        s = smtplib.SMTP('localhost')
        s.sendmail(fromAddr, toAddrs, msg.as_string(unixfrom=True))
        print "%sed message successfully sent to recipient %s" % (args.mode, toAddrs)

