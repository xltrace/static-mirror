# Static Mirror

A simple script which grabs a page (from e.g. wordpress), and its requirements, to populate a placeholder domain.

`/static-mirror.php?for=` initializes all needed documents, like *.htaccess*, *static-mirror.json*, *cache/* and *patch/*

With an empty `?for=` an rebuild is forced.
