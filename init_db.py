#!/usr/bin/env python
import getpass
import redis
import hashlib

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

db.set("users:{0}:hashed_pw".format(initial_admin), hashlib.md5(hashlib.md5(initial_admin_pass).hexdigest()).hexdigest())
db.sadd("admins", initial_admin)
db.sadd("users", initial_admin)
db.set("sitename", sitename)
