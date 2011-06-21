#!/usr/bin/env python
from flup.server.fcgi import WSGIServer
from squidink import app

if __name__ == '__main__':
    app.secret_key = ",j\x16!|5@\x8a\xe6&tLt\xd3\xd7\x00s\xaa[|\x89\xee\xe7-"  # required for session use
    app.debug = False
    WSGIServer(app).run()
