from setuptools import setup

setup(
    name='tpm2-pkcs11-tools',
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

    # Dependencies got here aka install_requires=['tensorflow']
    install_requires=[],
    tests_require=[],
    entry_points={
        'console_scripts': ['tpm2_ptool = tpm2_pkcs11.tpm2_ptool:main',],
    },)
