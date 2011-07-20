SquidInk
========

What is it?
-----------

SquidInk is my pet blogging engine project. It currently powers psquid.net, and
is not especially flexible in terms of theming. I intend to fix that as I
develop it further, though.


What do I need to run it?
-------------------------

It's written in Python, so you'll need that. Any 2.x-series version later than
2.5 should be fine. You'll also need:

* redis
* python-redis
* PyRSS2Gen
* python-markdown
* flask

The following Python packages are recommended, but not necessary; the functions they provide will simply be disabled if they're not present:

* statusnet (from IdentiCurse, or alternatively a different module with the same interface)
* pygments
