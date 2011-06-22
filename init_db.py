#!/usr/bin/env python
import getpass
import redis
import hashlib

KEY_BASE = "squidink:"  # change this to point to a different db if needed

db = redis.Redis()

while True:
    initial_admin = raw_input("What username should your initial admin have?\t").strip().lower()
    if initial_admin != "":
        break
while True:
    initial_admin_pass = getpass.getpass("What should your initial admin's password be?\t").strip().lower()
    if initial_admin_pass != "":
        break
while True:
    sitename = raw_input("What should your blog's title be?\t").strip()
    if sitename != "":
        break

db.set(KEY_BASE+"users:{0}:hashed_pw".format(initial_admin), hashlib.md5(hashlib.md5(initial_admin_pass).hexdigest()).hexdigest())
db.sadd(KEY_BASE+"admins", initial_admin)
db.sadd(KEY_BASE+"users", initial_admin)
db.set(KEY_BASE+"sitename", sitename)
