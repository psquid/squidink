#!/usr/bin/env python
from flup.server.fcgi import WSGIServer
# from werkzeug.contrib.fixers import LighttpdCGIRootFix
from squidink import app

if __name__ == '__main__':
    ### IMPORTANT: the secret key _must_ be changed before using SquidInk, otherwise the session will have a known key, meaning an attacker could easily spoof an admin session
    app.secret_key = ",j\x16!|5@\x8a\xe6&tLt\xd3\xd7\x00s\xaa[|\x89\xee\xe7-"  # required for session use
    app.debug = False
    # app.wsgi_app = LighttpdCGIRootFix(app.wsgi_app)
    WSGIServer(app).run()
