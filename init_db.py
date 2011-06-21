#!/usr/bin/env python
import getpass
import redis
import hashlib

db = redis.Redis()

while True:
    initial_admin = raw_input("What username should your initial admin have?\n").strip().lower()
    if initial_admin != "":
        break
while True:
    initial_admin_pass = raw_input("What should your initial admin's password be?\n").strip().lower()
    if initial_admin_pass != "":
        break
while True:
    sitename = raw_input("What should your site's title be?\n").strip().lower()
    if sitename != "":
        break

db.set("user:{0}:hashed_pw".format(initial_admin), hashlib.md5(hashlib.md5(initial_admin_pass).hex_digest()).hex_digest())
db.sadd("admins", initial_admin)
db.set("sitename", sitename)
