from __future__ import print_function

import binascii
import os
import sys
import struct


MAGICS = {
    20121: 'Python 1.5.x',
    50428: 'Python 1.6',
    50823: 'Python 2.0.x',
    60202: 'Python 2.1.x',
    60717: 'Python 2.2',
    62011: 'Python 2.3a0',
    62021: 'Python 2.3a0',
    62041: 'Python 2.4a0',
    62051: 'Python 2.4a3',
    62061: 'Python 2.4b1',
    62071: 'Python 2.5a0',
    62081: 'Python 2.5a0',
    62091: 'Python 2.5a0',
    62092: 'Python 2.5a0',
    62101: 'Python 2.5b3',
    62111: 'Python 2.5b3',
    62121: 'Python 2.5c1',
    62131: 'Python 2.5c2',
    62151: 'Python 2.6a0',
    62161: 'Python 2.6a1',
    62171: 'Python 2.7a0',
    62181: 'Python 2.7a0',
    62191: 'Python 2.7a0',
    62201: 'Python 2.7a0',
    62211: 'Python 2.7a0',
    3000: 'Python 3000',
    3010: 'Python 3000',
    3020: 'Python 3000',
    3030: 'Python 3000',
    3040: 'Python 3000',
    3050: 'Python 3000',
    3060: 'Python 3000',
    3061: 'Python 3000',
    3071: 'Python 3000',
    3081: 'Python 3000',
    3091: 'Python 3000',
    3101: 'Python 3000',
    3103: 'Python 3000',
    3111: 'Python 3.0a4',
    3131: 'Python 3.0b1',
    3141: 'Python 3.1a1',
    3151: 'Python 3.1a1',
    3160: 'Python 3.2a1',
    3170: 'Python 3.2a2',
    3180: 'Python 3.2a3',
    3190: 'Python 3.3a1',
    3200: 'Python 3.3a1',
    3210: 'Python 3.3a1',
    3220: 'Python 3.3a2',
    3230: 'Python 3.3a4',
    3250: 'Python 3.4a1',
    3260: 'Python 3.4a1',
    3270: 'Python 3.4a1',
    3280: 'Python 3.4a1',
    3290: 'Python 3.4a4',
    3300: 'Python 3.4a4',
    3310: 'Python 3.4rc2',
    3320: 'Python 3.5a1',
    3330: 'Python 3.5b1',
    3340: 'Python 3.5b2',
    3350: 'Python 3.5b3',
    3351: 'Python 3.5.2',
    3360: 'Python 3.6a0',
    3361: 'Python 3.6a1',
    3370: 'Python 3.6a2',
    3371: 'Python 3.6a2',
    3372: 'Python 3.6a2',
    3373: 'Python 3.6b1',
    3375: 'Python 3.6b1',
    3376: 'Python 3.6b1',
    3377: 'Python 3.6b1',
    3378: 'Python 3.6b2',
    3379: 'Python 3.6rc1',
    3390: 'Python 3.7a1',
    3391: 'Python 3.7a2',
    3392: 'Python 3.7a4',
    3393: 'Python 3.7b1',
    3394: 'Python 3.7b5',
    3400: 'Python 3.8a1',
    3401: 'Python 3.8a1',
}


def get_compiled_file_python_version(filename):
    """Get the version of Python by which the file was compiled"""
    ext = os.path.splitext(filename)[1]
    if not os.path.isfile(filename):
        print('File "%s" doesn\'t exist' % filename)
        return ''
    with open(filename, 'rb') as in_file:
        magic = in_file.read(4)
        magic_data = struct.unpack('H2B', magic)
        python_version = MAGICS.get(magic_data[0], '')
        if magic_data[1:] != (13, 10):
            magic_hex = binascii.hexlify(magic).decode()
            print('Wrong magic bytes "%s". Last two bytes must be "0d0a"!' % magic_hex)
            return ''
        if not python_version:
            print('Unknown Python version or wrong magic bytes!')
    return python_version


def main():
    """Main"""
    if len(sys.argv) < 2:
        sys.exit('Usage: %s <file>' % os.path.basename(sys.argv[0]))
    filename = sys.argv[1]
    python_version = get_compiled_file_python_version(filename)
    if python_version:
        print('File "%s" is compiled with: %s' % (filename, python_version))


if __name__ == '__main__':
    main()
