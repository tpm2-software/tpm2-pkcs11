from setuptools import setup

# read the contents of your README file
from os import path
readme = path.join(path.dirname(__file__), '..', 'docs', 'README.md')
with open(readme, encoding='utf-8') as f:
    long_description = f.read()

setup(
    name='tpm2-pkcs11-tools',
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='1.33.7',
    description='Command line tools for the TPM2.0 PKCS11 module',
    url='https://github.com/tpm2-software/tpm2-pkcs11',
    license='BSD2',
    keywords=['',],
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
        'cryptography',
        'pyyaml',
    ],
    tests_require=[],
    entry_points={
        'console_scripts': ['tpm2_ptool = tpm2_pkcs11.tpm2_ptool:main'],
    },
)
