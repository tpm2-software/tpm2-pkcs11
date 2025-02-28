# SPDX-License-Identifier: BSD-2-Clause
from setuptools import setup
from textwrap import dedent as DD

long_description = DD('''
   This tool is used to configure and manipulate stores for the tpm2-pkcs11
   cryptographic library.
''')

setup(
    name='tpm2-pkcs11-tools',
    python_requires='>=3.7',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='1.33.7',
    description='Command line tools for the TPM2.0 PKCS11 module',
    url='https://github.com/tpm2-software/tpm2-pkcs11',
    license='BSD2',
    keywords=['', ],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'License :: OSI Approved :: BSD License',
        'Environment :: Console',
        'Natural Language :: English',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
    ],
    packages=['tpm2_pkcs11'],

    # Dependencies got here aka install_requires=['tensorflow']
    install_requires=[
        'bcrypt',
        'cryptography>=3.0',
        'pyyaml',
        'pyasn1',
        'pyasn1_modules',
        'tpm2_pytss'
    ],
    entry_points={
        'console_scripts': ['tpm2_ptool = tpm2_pkcs11.tpm2_ptool:main'],
    }, )
