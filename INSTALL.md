libbadger
=========

This library has functions for retrieving records from the Namecoin blockchain.
It is implemented as the URI scheme `nmc:<block-name>`.  To take advantage
of the existing id namespace, the `id:<name>` URI scheme can be used as
shorthand for `nmc:id/<name>`.

If you would like to use libbadger without supporting namecoin records,
you can skip the next section.


Installing and Configuring namecoind
====================================

Configure namecoind to run as a daemon:

    $ mkdir ~/.namecoin
    $ cat <<EOF> ~/.namecoin/bitcoin.conf
    rpcuser=rpcuser
    rpcpassword=rpcpassword
    rpcport=8336
    daemon=1
    EOF

Build and run namecoind:

    $ git clone https://github.com/namecoin/namecoin
    $ cd namecoin/src
    $ make -f makefile.unix  # use correct makefile for your system
    $ ./namecoind

Now that the namecoin RPC service is running, you can build libbadger:

    $ git clone http://github.com/johnoliverdriscoll/badger
    $ mkdir badger_build && cd badger_build
    $ cmake ../badger
    $ make

You can create a record for yourself with `badger-record`.
Post the output of `badger-record` in the blockchain or on the web and
test badger:

    $ badger-key | badger-badge <id-url> MQ== | badger-verify
