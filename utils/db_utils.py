import sqlite3
from dataclasses import dataclass


def create_sql_table(db):
    try:
        import os
        if not os.path.exists(r'db'):
            os.makedirs(r'db')
        con = sqlite3.connect(db)
        cur = con.cursor()
        cur.execute(""" CREATE TABLE IF NOT EXISTS users (
                                            connectionid text PRIMARY KEY,
                                            npub text,
                                            secret text,
                                            lnbitskey text,
                                            lnbitsdomain text,
                                            lastactive integer
                                        ); """)
        cur.execute("SELECT name FROM sqlite_master")
        con.close()

    except Exception as e:
        print(e)

def add_to_sql_table(db, connectionid, npub, secret, lnbitskey, lnbitsdomain, lastactive):
    try:
        con = sqlite3.connect(db)
        cur = con.cursor()
        data = (connectionid, npub, secret, lnbitskey, lnbitsdomain, lastactive)
        cur.execute("INSERT or IGNORE INTO users VALUES(?, ?, ?, ?, ?, ?)", data)
        con.commit()
        con.close()
    except Exception as e:
        print("Error when Adding to DB: " + str(e))

def get_from_sql_table(db, npub):
    try:
        con = sqlite3.connect(db)
        cur = con.cursor()
        cur.execute("SELECT * FROM users WHERE npub=?", (npub,))
        row = cur.fetchone()
        con.close()
        if row is None:
            return None
        else:
            user = User
            user.connectionid = row[0]
            user.npub = row[1]
            user.secret = row[2]
            user.lnbitskey = row[3]
            user.lnbitsdomain = row[4]
            user.lastactive = row[5]

            return user

    except Exception as e:
        print("Error Getting from DB: " + str(e))


@dataclass
class User:
    connectionid: str
    npub: str
    secret: str
    lnbitskey: str
    lnbitsdomain: str
    lastactive: int

