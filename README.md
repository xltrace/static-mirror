# Static Mirror

A simple script which grabs a page (from e.g. wordpress), and its requirements, to populate a placeholder domain.

## Installation

Place the `static-mirror.php`-file in the directory of the domain you wish to be a mirror.

`/static-mirror.php?for=` initializes all needed documents, like *.htaccess*, *static-mirror.json*, *cache/* and *patch/*

With an empty `?for=` or `initial` an rebuild is forced.

## Configuration
`configure` lets you setup your static-mirror. It sets your secret token.

By use of the token you can `signin` and `signoff`, but also send encrypted Hermes-data.

## Management
`management` shows all modules.

### Upgrade
`upgrade` will upgrade your local static-mirror installation.

### Update
`update` will update your cached mirror.

### Backup

### Slaves
Your static-mirror can control other static-mirror's. You list the URIs as slaves.

#### `?all=true`
You can `upgrade?all=true` and `update?all=true` and `status.json?all=true` for your local static-mirror and all slaves.

### Duplicate
With use of the functionality `duplicate` you duplicate static-mirror to an other directory within your webserver. When you provide the URI, it will be added as slave.

### Decrypt

## status.json
Each implementation of static-mirror has an `status.json` file.

## Hermes

### remote.php
