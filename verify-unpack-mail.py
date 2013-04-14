"""
Using gpgMime to verify/decrypt email mime messages, and
    unpack the message if all things go right.

    Jay S. Liu
    jay.s.liu@gmail.com
    Mar. 24, 2013
    Version: 0.1
"""
import sys, os, email, os.path
import mimetypes
import gnupg
import gpgMime

def work(message, gpg, directory=None, _fileOut=True, **kwargs):
    r"""verify/decrypt the mime ``message``; unpack it
    into the specified ``directory`` if successful
    """
    ct = message.get_content_type()
    if ct == 'multipart/encrypted':
        message = gpgMime.decrypt(message, gpg, **kwargs)
        ct = message.get_content_type()
        if ct == 'multipart/signed':
            message, verified = gpgMime.verify(message, gpg, **kwargs)
            print 'Message signed by %s is verified OK.' % verified.username
        unpackMime(message, directory, _fileOut)
    elif ct == 'multipart/signed':
        message, verified = gpgMime.verify(message, gpg, **kwargs)
        print 'Message signed by %s is verified OK.' % verified.username
        unpackMime(message, directory, _fileOut)
    else:
        sys.stderr.write('!!! Wrong message type !!!\n')

def unpackMime(message, directory='tmp', _fileOut=True):
    r"""unpack the mime ``message`` into the specified ``directory``
    """
    counter = 1
    for part in message.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue
        # Applications should really sanitize the given filename so that an
        # email message can't be used to overwrite important files
        filename = part.get_filename()
        if not filename:
            ext = mimetypes.guess_extension(part.get_content_type())
            if not ext:
                # Use a generic bag-of-bits extension
                ext = '.bin'
            filename = 'part-%03d%s' % (counter, ext)
        else:
            filename = os.path.basename(filename)
        counter += 1
        if _fileOut:
            fp = open(os.path.join(directory, filename), 'wb')
            fp.write(part.get_payload(decode=True))
            fp.close()
        else:
            sys.stdout.write('\n----------\nAttached file ')
            sys.stdout.write(filename)
            sys.stdout.write(' with content:\n')
            sys.stdout.write(part.get_payload(decode=True))

def main():
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-f', '--message-file', metavar='FILE', required=True,
        help='the mime message file to be verified')
    parser.add_argument(
        '-d', '--directory', metavar='DIRECTORY',
        help='directory name to store unpacked files')
    parser.add_argument(
        '-p', '--passphrase', default=None,
        help="gpg private key passphrase for decryption")
    parser.add_argument(
        '--output', action='store_const', const=True,
        help="don't save file(s), print it to stdout instead")

    args = parser.parse_args()

    fp = open(args.message_file, 'U')
    msg = email.message_from_file(fp)
    fp.close()

    if args.output:
        _fileOut = False
    else:
        _fileOut = True

    gpg = gnupg.GPG()
    kwds = {}
    kwds = {'passphrase':args.passphrase}

    if args.directory:
        targetDir = args.directory
    else:
        targetDir = 'tmp' + str(os.getpid())
    if not os.path.exists(targetDir):
        os.mkdir(targetDir)

    work(msg, gpg, targetDir, _fileOut, **kwds)

if __name__ == '__main__':
    main()
