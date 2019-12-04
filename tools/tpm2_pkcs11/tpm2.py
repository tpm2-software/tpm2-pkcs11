from __future__ import print_function

import os
import sys
from tempfile import mkstemp, NamedTemporaryFile
import uuid

from subprocess import Popen, PIPE


class Tpm2(object):
    def __init__(self, tmp):
        self._tmp = tmp

    def createprimary(self, ownerauth, objauth, policy=None):
        ctx = os.path.join(self._tmp, "context.out")
        cmd = [
            'tpm2_createprimary', '-p', '%s' % objauth, '-c', ctx, '-g',
            'sha256', '-G', 'rsa'
        ]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend(['-P', ownerauth])

        if policy:
            cmd.extend(['-L', policy])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_createprimary: %s" %
                               stderr)
        return ctx

    def evictcontrol(self, ownerauth, ctx):

        tr_file = os.path.join(self._tmp, "primary.handle")

        cmd = ['tpm2_evictcontrol', '-c', str(ctx), '-o', tr_file]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend(['-P', ownerauth])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_evictcontrol: %s",
                               stderr)
        return tr_file

    def readpublic(self, handle):

        tr_file = os.path.join(self._tmp, "primary.handle")

        cmd = ['tpm2_readpublic', '-c', str(handle), '-t', tr_file]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        stdout, stderr = p.communicate()
        if (p.wait()):
            raise RuntimeError("Could not execute tpm2_readpublic: %s",
                               stderr)
        return tr_file

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
                'tpm2_load', '-C', str(pctx), '-P', pauth, '-u', pub, '-r',
                priv, '-n', '/dev/null', '-c', ctx
            ]
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
               pauth,
               objauth=None,
               objattrs=None,
               seal=None,
               alg=None,
               policy=None):
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

        if policy:
            cmd.extend(['-L', policy])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, stdin=PIPE, env=os.environ)
        stdout, stderr = p.communicate(input=seal)
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

    def changeauth(self, is_not_nv, pctx, objctx, oldobjauth, newobjauth):

        newpriv = os.path.join(self._tmp, uuid.uuid4().hex + '.priv')

        #tpm2_load -C $file_primary_key_ctx  -u $file_load_key_pub  -r $file_load_key_priv -n $file_load_key_name -o $file_load_key_ctx
        cmd = ['tpm2_changeauth', '-c', str(objctx), '-p', oldobjauth, newobjauth]

        if is_not_nv:
            cmd.extend(['-C', str(pctx), '-r', newpriv])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_load: %s", stderr)

        if is_not_nv:
            return newpriv

    def startauthsession(self, is_policy_session):

        session_ctx = os.path.join(self._tmp, uuid.uuid4().hex + '.sessionctx')
        cmd = ['tpm2_startauthsession', '-S', session_ctx]

        if is_policy_session:
            cmd.extend(['--policy-session'])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_startauthsession: %s", stderr)

        return session_ctx

    def flushsession(self, session_ctx):

        cmd = ['tpm2_flushcontext', session_ctx]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_startauthsession: %s", stderr)

        return session_ctx

    def createpolicypassword(self, session_ctx):

        policypassword = os.path.join(self._tmp, uuid.uuid4().hex + '.policypassword')
        cmd = ['tpm2_policypassword', '-S', session_ctx, '-L', policypassword]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_startauthsession: %s", stderr)

        return policypassword, session_ctx

    def nvindexdefine(self, ownerauth, nvindexauth, policyfile):

        # tpm2_nvdefine -C o -P ownerauth -p defaultsonvpin $NV_INDEX \
        # -a "authread|authwrite" -s 0 -L policy.pass_AND_ccnvobjch
        cmd = [
            'tpm2_nvdefine', '-C', 'o', '-s', '0', '-L', policyfile,
            '-a', 'authread|authwrite'
        ]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend(['-P', ownerauth])

        if nvindexauth and len(nvindexauth) > 0:
            cmd.extend(['-p', '%s' % nvindexauth])


        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        outputnvindexstr, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_nvdefine: %s", stderr)
            return 0

        return outputnvindexstr

    def nvindexundefine(self, ownerauth, nvindex):

        #tpm2_nvundefine -C o -P ownerauth $NV_INDEX
        cmd = ['tpm2_nvundefine', '-C', 'o', nvindex]

        if ownerauth and len(ownerauth) > 0:
            cmd.extend(['-P', ownerauth])

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_nvundefine: %s", stderr)


    def policycommandcode(self, commandcode, session_ctx):

        policycommandcode = os.path.join(self._tmp, uuid.uuid4().hex + '.policycommandcode')
        #tpm2_policycommandcode -S session.ctx -L policy_output
        cmd = ['tpm2_policycommandcode', '-S', session_ctx, '-L', policycommandcode, commandcode]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_policycommandcode: %s", stderr)

        return policycommandcode, session_ctx

    def policysecret(self, tpm2object, tpm2objectauth, session_ctx):

        #tpm2_policysecret -S session_ctx -c tpm2object tpm2objectauth
        policysecret = os.path.join(self._tmp, uuid.uuid4().hex + '.policysecret')
        cmd = ['tpm2_policysecret', '-S', session_ctx, '-L', policysecret,
                '-c', tpm2object, tpm2objectauth]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_policysecret: %s", stderr)

        return policysecret, session_ctx

    def policyor(self, policy_truth_value1, policy_truth_value2, session_ctx):
        policyor = os.path.join(self._tmp, uuid.uuid4().hex + '.policyor')
        #tpm2_policyor -S session.ctx -L policy_output -l sha256:t1,t2
        cmd = ['tpm2_policyor', '-S', session_ctx, '-L', policyor,
               '-l', 'sha256:'+policy_truth_value1+','+policy_truth_value2]

        p = Popen(cmd, stdout=PIPE, stderr=PIPE, env=os.environ)
        _, stderr = p.communicate()
        rc = p.wait()
        if rc:
            raise RuntimeError("Could not execute tpm2_policyor: %s", stderr)

        return policyor, session_ctx
