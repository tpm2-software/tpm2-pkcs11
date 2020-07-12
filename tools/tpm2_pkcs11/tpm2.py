# SPDX-License-Identifier: BSD-2-Clause
from __future__ import print_function
import os
import sys
from tempfile import mkstemp, NamedTemporaryFile
import uuid


from subprocess import Popen, PIPE

from .utils import str2bytes

class Tpm2(object):
    TPM2_RH_OWNER = 0x40000001
    TPM2_HR_SHIFT = 24
    TPM2_HT_PERSISTENT = 0x81

    _TSS2_DEFAULT_ATTRS = "userwithauth|restricted|decrypt|noda|fixedtpm" \
        "|fixedparent|sensitivedataorigin"

    ALGS = [
        'rsa1024', 'rsa2048', 'aes128', 'aes256', 'ecc224', 'ecc256',
        'ecc384', 'ecc521'
    ]

    TEMPLATES = {
        # No selection, just use an rsa2048 with tpm2-tool default attrs
        None               : {
            'alg' : 'rsa2048',
            'attrs' : None
        },
        # tss2-engine key compatible with EC p256
        'tss2-engine-key' :  {
            'alg' : None,
            'attrs' : _TSS2_DEFAULT_ATTRS
        }
    }

    def __init__(self, tmp):
        self._tmp = tmp

    @property
    def tmpdir(self):
        return self._tmp

    def createprimary(self, hierarchyauth=None, objauth=None, alg=None, attrs=None,):
        ctx = os.path.join(self._tmp, "context.out")
        cmd = [
            'tpm2_createprimary', '-c', ctx, '-g',
            'sha256'
        ]

        if alg is None:
            alg = 'rsa'

        cmd.extend(['-G', alg])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', objauth])

        if hierarchyauth and len(hierarchyauth) > 0:
            cmd.extend(['-P', hierarchyauth])

        if attrs is not None:
            cmd.extend(['-a', attrs])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_createprimary: %s" %
                               stderr)
        return ctx

    def evictcontrol(self, hierarchyauth, ctx):

        tr_file = os.path.join(self._tmp, "primary.handle")

        cmd = ['tpm2_evictcontrol', '-c', str(ctx), '-o', tr_file]

        if hierarchyauth and len(hierarchyauth) > 0:
            cmd.extend(['-P', hierarchyauth])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_evictcontrol: %s",
                               stderr)
        return tr_file

    def readpublic(self, handle, get_tr_file=True):

        tr_file = os.path.join(self._tmp, "primary.handle")

        cmd = ['tpm2_readpublic', '-c', str(handle)]

        if get_tr_file:
            cmd.extend(['-t', tr_file])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_readpublic: %s",
                               stderr)
        return (stdout, tr_file if get_tr_file else None)

    def load(self, pctx, pauth, priv, pub):

        if priv != None and not isinstance(priv, str):
            sealprivf = NamedTemporaryFile()
            sealprivf.write(priv)
            sealprivf.flush()
            priv = sealprivf.name

        if not isinstance(pub, str):
            sealpubf = NamedTemporaryFile()
            sealpubf.write(pub)
            sealpubf.flush()
            pub = sealpubf.name

        ctx = os.path.join(self._tmp, uuid.uuid4().hex + '.out')
        #tpm2_load -C $file_primary_key_ctx  -u $file_load_key_pub  -r $file_load_key_priv -n $file_load_key_name -c $file_load_key_ctx
        if priv != None:
            cmd = [
                'tpm2_load', '-C', str(pctx), '-u', pub, '-r',
                priv, '-n', '/dev/null', '-c', ctx
            ]
            if pauth is not None:
                cmd.extend(['-P', pauth])
        else:
            cmd = ['tpm2_loadexternal', '-u', pub, '-c', ctx]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)
        return ctx

    def unseal(self, ctx, auth):

        # tpm2_unseal -Q -c $file_unseal_key_ctx
        cmd = ['tpm2_unseal', '-c', ctx, '-p', auth]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_unseal: %s", stderr)
        return stdout

    def _encryptdecrypt(self, ctx, auth, data, decrypt=False):

        cmd = ['tpm2_encryptdecrypt', '-c', ctx, '-p', auth]

        if decrypt:
            cmd.extend(['-d'])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=data)
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_encryptdecrypt: %s",
                               stderr)
        return stdout

    def encrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data)

    def decrypt(self, ctx, auth, data):
        return self._encryptdecrypt(ctx, auth, data, decrypt=True)

    def create(self,
               phandle,
               pauth=None,
               objauth=None,
               objattrs=None,
               seal=None,
               alg=None):
        # tpm2_create -Q -C context.out -g $gAlg -G $GAlg -u key.pub -r key.priv
        _, priv = mkstemp(prefix='', suffix='.priv', dir=self._tmp)
        _, pub = mkstemp(prefix='', suffix='.pub', dir=self._tmp)

        cmd = ['tpm2_create', '-C', str(phandle), '-u', pub, '-r', priv]

        if pauth and len(pauth) > 0:
            cmd.extend(['-P', '%s' % pauth])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', objauth])

        if objattrs != None:
            cmd.extend(['-a', objattrs])

        if seal != None:
            cmd.extend(['-i', '-'])

        if alg != None:
            cmd.extend(['-G', alg])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=str2bytes(seal))
        rc = p.wait()
        if (rc != 0):
            os.remove(pub)
            os.remove(priv)
            raise RuntimeError("Could not execute tpm2_create: %s" %
                               str(stderr))

        return priv, pub, stdout

    def getcap(self, cap):

        # tpm2_getcap -Q -l $cap
        cmd = ['tpm2_getcap', cap]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_getcap: %s", stderr)
        return stdout

    def importkey(self,
                  phandle,
                  pauth,
                  objauth,
                  privkey,
                  objattrs=None,
                  seal=None,
                  alg=None):

        if privkey and len(privkey) > 0:
            exists = os.path.isfile(privkey)
            if not exists:
                raise RuntimeError("File '%s' path is invalid or is missing",
                                   privkey)
        else:
            sys.exit("Invalid file path")

        _, priv = mkstemp(prefix='', suffix='.priv', dir=self._tmp)
        _, pub = mkstemp(prefix='', suffix='.pub', dir=self._tmp)

        parent_path = str(phandle)
        cmd = [
            'tpm2_import', '-V', '-C', parent_path, '-i', privkey, '-u', pub,
            '-r', priv
        ]

        if pauth and len(pauth) > 0:
            cmd.extend(['-P', pauth])

        if objauth and len(objauth) > 0:
            cmd.extend(['-p', objauth])

        if objattrs != None:
            cmd.extend(['-a', objattrs])

        if seal != None:
            cmd.extend(['-i', '-'])

        if alg != None:
            cmd.extend(['-G', alg])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=seal)
        rc = p.wait()
        if (rc != 0):
            os.remove(pub)
            os.remove(priv)
            print("command: %s" % str(" ".join(cmd)))
            raise RuntimeError("Could not execute tpm2_import: %s" %
                               str(stderr))

        return priv, pub, stdout

    def changeauth(self, pctx, objctx, oldobjauth, newobjauth):

        newpriv = os.path.join(self._tmp, uuid.uuid4().hex + '.priv')

        cmd = [
            'tpm2_changeauth',
            '-C',
            str(pctx),
            '-c',
            str(objctx),
            '-p',
            oldobjauth,
            '-r',
            newpriv,
            newobjauth,
        ]
        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_changeauth: %s", stderr)

        return newpriv

    def sign(self, ctx, halg, scheme, message):

        sig = os.path.join(self._tmp, uuid.uuid4().hex + '.dat')

        cmd = [
            'tpm2_sign',
            '-c',
            str(ctx),
            '-g', halg,
            '-s', scheme,
            '-f',
            'plain',
            '-o',
            sig
        ]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=str2bytes(message))
        rc = p.wait()
        if (rc != 0):
            print("command: %s" % str(" ".join(cmd)))
            raise RuntimeError("Could not execute tpm2_import: %s" %
                               str(stderr))
        data = open(sig, "rb").read()
        os.unlink(sig)
        return data
