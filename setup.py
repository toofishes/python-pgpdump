from distutils.core import setup

from pgpdump import __version__, __author__

classifiers = [
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: BSD License',
    'Programming Language :: Python',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries :: Python Modules'
]

setup(
    name = 'pgpdump',
    version = __version__,
    author = __author__,
    license = 'BSD',
    description = 'PGP packet parser library',
    url = 'https://github.com/toofishes/python-pgpdump',
    keywords = 'pgp gpg rfc2440 rfc4880 crypto cryptography',
    classifiers = classifiers,
    packages = ['pgpdump']
)
