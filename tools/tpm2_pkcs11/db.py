import textwrap
import os
import sys
import sqlite3

from .utils import list_dict_to_kvp
from .utils import dict_to_kvp

#
# With Db() as db:
# // do stuff
#
class Db(object):
    def __init__(self, dirpath):
        self._path = os.path.join(dirpath, "tpm2_pkcs11.sqlite3")

    def __enter__(self):
        self._conn = sqlite3.connect(self._path)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute('PRAGMA foreign_keys = ON;')

        return self

    @staticmethod
    def _blobify(path):
        with open(path, 'rb') as f:
            ablob = f.read()
            return sqlite3.Binary(ablob)

    def gettoken(self, label):
        c = self._conn.cursor()
        c.execute("SELECT * from tokens WHERE label=?", (label, ))
        x = c.fetchone()
        if x is None:
            sys.exit('No token labeled "%s"' % label)
        return x

    def getsealobject(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from sealobjects WHERE tokid=?", (tokid, ))
        x = c.fetchone()
        return x

    def gettokens(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from tokens WHERE pid=?", (pid, ))
        x = c.fetchall()
        return x

    def rmtoken(self, label):
        # This works on the premise of a cascading delete tied by foriegn
        # key relationships.
        self._conn.execute('DELETE from tokens WHERE label=?', (label, ))

    def getprimary(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from pobjects WHERE id=?", (pid, ))
        x = c.fetchone()
        return x

    def rmprimary(self, pid):
        # This works on the premise of a cascading delete tied by foriegn
        # key relationships.
        self._conn.execute('DELETE from pobjects WHERE id=?', (pid, ))

    def gettertiary(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE tokid=?", (tokid, ))
        x = c.fetchall()
        return x

    def addtoken(self, pid, config, label=None):

        token = {
            # General Metadata
            'pid': pid,
            'config': dict_to_kvp(config)
        }

        if 'token-init=True' in token['config'] and label is None:
            raise RuntimeError('Expected label if token is to be initialized')

        if label:
            token['label'] = label

        columns = ', '.join(token.keys())
        placeholders = ', '.join('?' * len(token))
        sql = 'INSERT INTO tokens ({}) VALUES ({})'.format(columns,
                                                           placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(token.values()))

        return c.lastrowid

    def updateconfig(self, token, config):

        new_config = dict_to_kvp(config)

        sql = 'UPDATE tokens SET config=? WHERE id=?'

        values = (new_config, token['id'])

        c = self._conn.cursor()
        c.execute(sql, values)

    def addsealobjects(self, tokid, usersealauth, usersealpriv, usersealpub,
                       sosealauth, sosealpriv, sosealpub):

        sealobjects = {
            # General Metadata
            'tokid': tokid,
            'userpriv': Db._blobify(usersealpriv),
            'userpub': Db._blobify(usersealpub),
            'sopriv': Db._blobify(sosealpriv),
            'sopub': Db._blobify(sosealpub),
            'userauthsalt': usersealauth['salt'],
            'soauthsalt': sosealauth['salt'],
        }

        columns = ', '.join(sealobjects.keys())
        placeholders = ', '.join('?' * len(sealobjects))
        sql = 'INSERT INTO sealobjects ({}) VALUES ({})'.format(columns,
                                                                placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(sealobjects.values()))

        return c.lastrowid

    def addprimary(self, tr_handle, objauth, hierarchy='o'):

        # Subordiante commands will need some of this data
        # when deriving subordinate objects, so pass it back
        pobject = {
            # General Metadata
            'hierarchy': hierarchy,
            'handle': Db._blobify(tr_handle),
            'objauth': objauth,
        }

        columns = ', '.join(pobject.keys())
        placeholders = ', '.join('?' * len(pobject))
        sql = 'INSERT INTO pobjects ({}) VALUES ({})'.format(columns,
                                                             placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(pobject.values()))

        return c.lastrowid

    def addtertiary(self, tokid, priv, pub, objauth, mech, attrs):
        tobject = {
            'tokid': tokid,
            'pub': Db._blobify(pub),
            'objauth': objauth,
            'mech': list_dict_to_kvp(mech),
            'attrs': list_dict_to_kvp(attrs),
        }

        if priv != None:
            tobject['priv'] = Db._blobify(priv)

        columns = ', '.join(tobject.keys())
        placeholders = ', '.join('?' * len(tobject))
        sql = 'INSERT INTO tobjects ({}) VALUES ({})'.format(columns,
                                                             placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(tobject.values()))
        return c.lastrowid

    def updatetertiaryattrs(self, tid, attrs):

        c = self._conn.cursor()
        attrs = list_dict_to_kvp(attrs)
        values = [attrs, tid]

        sql = 'UPDATE tobjects SET attrs=? WHERE id=?'

        c.execute(sql, values)

    def updatepin(self, is_so, token, sealauth, sealpriv, sealpub=None):

        tokid = token['id']

        c = self._conn.cursor()

        # TABLE sealobjects UPDATE
        # [user|so]priv TEXT NOT NULL,
        # [user|so]pub TEXT NOT NULL,
        # [user|so]authsalt TEXT NOT NULL,

        if sealpub:
            sql = 'UPDATE sealobjects SET {}authsalt=?, {}priv=?, {}pub=? WHERE id=?;'.format(
                * ['so' if is_so else 'user'] * 3)
            c.execute(sql, (sealauth['salt'], Db._blobify(sealpriv),
                            Db._blobify(sealpub), tokid))
        else:
            sql = 'UPDATE sealobjects SET {}authsalt=?, {}priv=? WHERE id=?;'.format(
                * ['so' if is_so else 'user'] * 2)
            c.execute(sql, (sealauth['salt'], Db._blobify(sealpriv), tokid))

    def commit(self):
        self._conn.commit()

    def __exit__(self, exc_type, exc_value, traceback):
        self._conn.commit()
        self._conn.close()

    def delete(self):
        try:
            os.remove(self._path)
        except OSError:
            pass

    # TODO collapse object tables into one, since they are common besides type.
    # move sealobject metadata into token metadata table.
    #
    # Object types:
    # soseal
    # userseal
    # wrapping
    # secondary
    # tertiary
    #
    # NOTE: Update the DB Schema Version at the bottom if the db format changes!
    def create(self):
        c = self._conn.cursor()
        sql = [
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS tokens(
                id INTEGER PRIMARY KEY,
                pid INTEGER NOT NULL,
                label TEXT UNIQUE,
                config TEXT NOT NULL,
                FOREIGN KEY (pid) REFERENCES pobjects(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS sealobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                userpub BLOB NOT NULL,
                userpriv BLOB NOT NULL,
                userauthsalt TEXT NOT NULL,
                sopub BLOB NOT NULL,
                sopriv BLOB NOT NULL,
                soauthsalt TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS pobjects(
                id INTEGER PRIMARY KEY,
                hierarchy TEXT NOT NULL,
                handle BLOB NOT NULL,
                objauth TEXT NOT NULL
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS tobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                pub BLOB NOT NULL,
                priv BLOB,
                objauth TEXT NOT NULL,
                mech TEXT NOT NULL,
                attrs TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE IF NOT EXISTS schema(
                id INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL
            );
            '''),
            # NOTE: Update the DB Schema Version if the format above changes!
            # REPLACE updates the value if it exists, or inserts it if it doesn't
            textwrap.dedent('''
                REPLACE INTO schema (id, schema_version) VALUES (1, 1);
            '''),
        ]

        for s in sql:
            c.execute(s)
