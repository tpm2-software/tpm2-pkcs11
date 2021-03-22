# SPDX-License-Identifier: BSD-2-Clause
import fcntl
import io
import os
import sys
import sqlite3
import textwrap
import yaml

from .pkcs11t import (
    CKA_ALLOWED_MECHANISMS,
    CKA_CLASS,
    CKO_SECRET_KEY,
    CKA_KEY_TYPE,
    CKM_AES_CBC_PAD,
    CKK_AES
)

VERSION = 5

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
        self._create()

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

    def getprimaries(self):
        c = self._conn.cursor()
        c.execute("SELECT * from pobjects")
        x = c.fetchall()
        return x

    def gettokens(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from tokens WHERE pid=?", (pid, ))
        x = c.fetchall()
        return x

    def getobjects(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE tokid=?", (tokid, ))
        x = c.fetchall()
        return x

    def rmtoken(self, label):
        # This works on the premise of a cascading delete tied by foreign
        # key relationships.
        self._conn.execute('DELETE from tokens WHERE label=?', (label, ))

    def getprimary(self, pid):
        c = self._conn.cursor()
        c.execute("SELECT * from pobjects WHERE id=?", (pid, ))
        x = c.fetchone()
        return x

    def rmprimary(self, pid):
        # This works on the premise of a cascading delete tied by foreign
        # key relationships.
        self._conn.execute('DELETE from pobjects WHERE id=?', (pid, ))

    def gettertiary(self, tokid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE tokid=?", (tokid, ))
        x = c.fetchall()
        return x

    def getobject(self, tid):
        c = self._conn.cursor()
        c.execute("SELECT * from tobjects WHERE id=?", (tid, ))
        x = c.fetchone()
        return x

    def rmobject(self, tid):
        c = self._conn.cursor()
        c.execute("DELETE FROM tobjects WHERE id=?", (tid, ))

    def addtoken(self, pid, config, label=None):

        token = {
            # General Metadata
            'pid': pid,
            'config': yaml.dump(config, canonical=True)
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

        new_config = yaml.dump(config, canonical=True)

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

    @staticmethod
    def addprimary_raw(cursor, tablename, config, objauth, hierarchy='o', pid=None):

        # Subordinate commands will need some of this data
        # when deriving subordinate objects, so pass it back
        pobject = {
            # General Metadata
            'hierarchy': hierarchy,
            'config': yaml.safe_dump(config, canonical=True),
            'objauth': objauth,
        }

        if pid is not None:
            pobject['id'] = pid

        columns = ', '.join(pobject.keys())
        placeholders = ', '.join('?' * len(pobject))
        sql = 'INSERT INTO {} ({}) VALUES ({})'.format(tablename,
                                                       columns,
                                                       placeholders)
        cursor.execute(sql, list(pobject.values()))

        return cursor.lastrowid

    def addprimary(self, config, objauth, hierarchy='o'):

        c = self._conn.cursor()
        return self.addprimary_raw(c, 'pobjects', config, objauth, hierarchy)

    def addtertiary(self, tokid, pkcs11_object):
        tobject = {
            'tokid': tokid,
            'attrs': yaml.safe_dump(dict(pkcs11_object), canonical=True),
        }

        columns = ', '.join(tobject.keys())
        placeholders = ', '.join('?' * len(tobject))
        sql = 'INSERT INTO tobjects ({}) VALUES ({})'.format(columns,
                                                             placeholders)
        c = self._conn.cursor()
        c.execute(sql, list(tobject.values()))
        return c.lastrowid

    @staticmethod
    def _updatetertiary(db, tid, attrs):
        c = db.cursor()
        attrs = yaml.safe_dump(attrs, canonical=True)
        values = [attrs, tid]

        sql = 'UPDATE tobjects SET attrs=? WHERE id=?'
        c.execute(sql, values)

    def updatetertiary(self, tid, attrs):

        self._updatetertiary(self._conn, tid, attrs)

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
        if (self._conn):
            self._conn.commit()
            self._conn.close()

    def delete(self):
        try:
            os.remove(self._path)
        except OSError:
            pass

    def backup(self):
        con = self._conn
        dbpath = self._path + ".bak"
        if os.path.exists(dbpath):
            raise RuntimeError("Backup DB exists at {} not overwriting. "
                "Refusing to run".format(dbpath))
        bck = sqlite3.connect(dbpath)
        con.backup(bck)
        return (bck, dbpath)

    def _update_on_2(self, dbbakcon):
        '''
        Between version 1 and 2 of the DB the following changes need to be made:
            The existing rows:
              - userpub BLOB NOT NULL,
              - userpriv BLOB NOT NULL,
              - userauthsalt TEXT NOT NULL,
            All have the "NOT NULL" constarint removed, like so:
                userpub BLOB,
                userpriv BLOB,
                userauthsalt TEXT
        So we need to create a new table with this constraint removed,
        copy the data and move the table back
        '''

        # Create a new table to copy data to that has the constraints removed
        s = textwrap.dedent('''
            CREATE TABLE sealobjects_new2(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                userpub BLOB,
                userpriv BLOB,
                userauthsalt TEXT,
                sopub BLOB NOT NULL,
                sopriv BLOB NOT NULL,
                soauthsalt TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            ''')
        dbbakcon.execute(s)

        # copy the data
        s = textwrap.dedent('''
            INSERT INTO sealobjects_new2
            SELECT * FROM sealobjects;
        ''')
        dbbakcon.execute(s)

        # Drop the old table
        s = 'DROP TABLE sealobjects;'
        dbbakcon.execute(s)

        # Rename the new table to the correct table name
        s = 'ALTER TABLE sealobjects_new2 RENAME TO sealobjects;'
        dbbakcon.execute(s)

        # Add the triggers
        sql = [
            textwrap.dedent('''
                CREATE TRIGGER limit_tokens
                BEFORE INSERT ON tokens
                BEGIN
                    SELECT CASE WHEN
                        (SELECT COUNT (*) FROM tokens) >= 255
                    THEN
                        RAISE(FAIL, "Maximum token count of 255 reached.")
                    END;
                END;
            '''),
            textwrap.dedent('''
                CREATE TRIGGER limit_tobjects
                BEFORE INSERT ON tobjects
                BEGIN
                    SELECT CASE WHEN
                        (SELECT COUNT (*) FROM tobjects) >= 16777215
                    THEN
                        RAISE(FAIL, "Maximum object count of 16777215 reached.")
                    END;
                END;
            ''')
        ]
        for s in sql:
            dbbakcon.execute(s)

    def _update_on_3(self, dbbakcon):
        dbbakcon.execute('DROP TRIGGER limit_tobjects;')

    def _update_on_4(self, dbbakcon):
        '''
        Between version 3 and 1 of the DB the following changes need to be made:
        Table pobjects:
          - column handle of type blob was changes to config of type string

        The YAML config has the handle of the ESYS_TR blob as a hex string.
        So to perform the upgrade, the code needs to create a new db and copy
        everything over and generate the new config YAML as:
        ----
        persistent: true
        esys-tr: bytes.hex(handle)
        '''

        # Create a new table to copy data to
        s = textwrap.dedent('''
            CREATE TABLE pobjects2 (
                id INTEGER PRIMARY KEY,
                hierarchy TEXT NOT NULL,
                config TEXT NOT NULL,
                objauth TEXT NOT NULL
            );
            ''')
        dbbakcon.execute(s)

        c = dbbakcon.cursor()

        c.execute('SELECT * from pobjects')
        old_pobjects = c.fetchall()

        # copy the data and take the old handle (ESYS_TR Blob)
        # and convert to a hexstring and store in the config.
        # add the pobject to the new table keep the rest of the values.
        # Note: All migrating pobjects are persistent so mark as such.
        for pobj in old_pobjects:
            pid = pobj['id']
            blob = pobj['handle']
            hexblob = bytes.hex(blob)

            config = {
                'persistent' : True,
                'esys-tr': hexblob
            }

            objauth = pobj['objauth']
            hierarchy = pobj['hierarchy']
            self.addprimary_raw(c, 'pobjects2', config, objauth,
                                hierarchy, pid)

        # Drop the old table
        s = 'DROP TABLE pobjects;'
        dbbakcon.execute(s)

        # Rename the new table to the correct table name
        s = 'ALTER TABLE pobjects2 RENAME TO pobjects;'
        dbbakcon.execute(s)

    def _update_on_5(self, dbbakcon):
        '''
        Between version 4 and 5 of the DB the following changes need to be made:

        Table tobjects:

        The YAML attributes need to include CKM_AES_CBC_PAD and CKM_AES_CTR in the
        CKM_ALLOWED_MECHANISMS list.
        '''

        c = dbbakcon.cursor()

        c.execute('SELECT * from tobjects')
        tobjs = c.fetchall()

        for t in tobjs:
            attrs = yaml.safe_load(io.StringIO(t['attrs']))

            # IF the object is definitely a SECRET KEY of AES and has
            # CKM_AES_CBC_PAD AND CKM_AES_CTR in allowed mechanisms, skip it.
            if CKA_CLASS not in attrs or \
                attrs[CKA_CLASS] != CKO_SECRET_KEY or \
                CKA_KEY_TYPE not in attrs or \
                attrs[CKA_KEY_TYPE] != CKK_AES or \
                CKA_ALLOWED_MECHANISMS not in attrs \
                (CKM_AES_CBC_PAD in attrs[CKA_ALLOWED_MECHANISMS] \
                 and \
                 CKM_AES_CTR in attrs[CKA_ALLOWED_MECHANISMS]):
                continue

            # Is an AES KEY and needs CKM_AES_CBC_PAD
            if not CKM_AES_CBC_PAD in attrs[CKA_ALLOWED_MECHANISMS]:
                attrs[CKA_ALLOWED_MECHANISMS].append(CKM_AES_CBC_PAD)

            # Is an AES KEY and needs CKM_AES_CBC_PAD
            if not CKM_AES_CTR in attrs[CKA_ALLOWED_MECHANISMS]:
                attrs[CKA_ALLOWED_MECHANISMS].append(CKM_AES_CBC_PAD)

            Db._updatetertiary(dbbakcon, t['id'], attrs)


    def update_db(self, old_version, new_version=VERSION):

        # were doing the update, so make a backup to manipulate
        (dbbakcon, dbbakpath) = self.backup()

        dbbakcon.row_factory = sqlite3.Row

        try:
            for x in range(old_version, new_version):
                x = x + 1
                getattr(self, '_update_on_{}'.format(x))(dbbakcon)

            sql = textwrap.dedent('''
                    REPLACE INTO schema (id, schema_version) VALUES (1, {version});
                '''.format(version=new_version))
            dbbakcon.execute(sql)
        finally:
            # Close the connections
            self._conn.commit()
            self._conn.close()

            dbbakcon.commit()
            dbbakcon.close()

            # move old db to ".old" suffix
            olddbpath = self._path + ".old"
            os.rename(self._path, olddbpath)

            # move the backup to the normal dbpath
            os.rename(dbbakpath, self._path)

            # unlink the old
            os.unlink(olddbpath)

            # re-establish a connection
            self._conn = sqlite3.connect(self._path)
            self._conn.row_factory = sqlite3.Row

    def _get_version(self):
        c = self._conn.cursor()
        try:
            c.execute('select schema_version from schema')
            return c.fetchone()[0]
        except sqlite3.OperationalError:
            return 0

    def db_init_new(self):

        c = self._conn.cursor()

        sql = [
            textwrap.dedent('''
            CREATE TABLE tokens(
                id INTEGER PRIMARY KEY,
                pid INTEGER NOT NULL,
                label TEXT UNIQUE,
                config TEXT NOT NULL,
                FOREIGN KEY (pid) REFERENCES pobjects(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE sealobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                userpub BLOB,
                userpriv BLOB,
                userauthsalt TEXT,
                sopub BLOB NOT NULL,
                sopriv BLOB NOT NULL,
                soauthsalt TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE pobjects(
                id INTEGER PRIMARY KEY,
                hierarchy TEXT NOT NULL,
                config TEXT NOT NULL,
                objauth TEXT NOT NULL
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE tobjects(
                id INTEGER PRIMARY KEY,
                tokid INTEGER NOT NULL,
                attrs TEXT NOT NULL,
                FOREIGN KEY (tokid) REFERENCES tokens(id) ON DELETE CASCADE
            );
            '''),
            textwrap.dedent('''
            CREATE TABLE schema(
                id INTEGER PRIMARY KEY,
                schema_version INTEGER NOT NULL
            );
            '''),
            textwrap.dedent('''
                CREATE TRIGGER limit_tokens
                BEFORE INSERT ON tokens
                BEGIN
                    SELECT CASE WHEN
                        (SELECT COUNT (*) FROM tokens) >= 255
                    THEN
                        RAISE(FAIL, "Maximum token count of 255 reached.")
                    END;
                END;
            '''),
            textwrap.dedent('''
                CREATE TRIGGER limit_tobjects
                BEFORE INSERT ON tobjects
                BEGIN
                    SELECT CASE WHEN
                        (SELECT COUNT (*) FROM tobjects) >= 16777215
                    THEN
                        RAISE(FAIL, "Maximum object count of 16777215 reached.")
                    END;
                END;
            '''),
            textwrap.dedent('''
                REPLACE INTO schema (id, schema_version) VALUES (1, {version});
            '''.format(version=VERSION))
        ]

        for s in sql:
            c.execute(s)

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
    def _do_create(self):

        # perform an update if we need to
        dbbakpath = None
        try:
            old_version = self._get_version()

            if old_version == 0:
                self.db_init_new()
                self.version = VERSION
                self.VERSION = VERSION
                return False
            elif VERSION == old_version:
                self.version = old_version
                self.VERSION = old_version
                return False
            elif old_version > VERSION:
                raise RuntimeError("DB Version exceeds library version:"
                 " {} > {}".format(old_version, VERSION))
            else:
                self.version = old_version
                self.update_db(old_version, VERSION)
                self.VERSION = self._get_version()
                return True

        except Exception as e:
            sys.stderr.write('DB Upgrade failed: "{}", backup located in "{}"'.format(e, dbbakpath))
            raise e

    def _create(self):

        # create a lock from the db name plush .lock suffix
        lockpath = self._path+".lock"
        holds_lock = False
        fd = os.open(lockpath, os.O_CREAT|os.O_RDWR)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            holds_lock = True
            self._do_create()
        finally:
            # we always want unlink to occur
            os.unlink(lockpath)
            if holds_lock:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
