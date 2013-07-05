Badger
======
![Badger](http://www.wpclipart.com/animals/B/badger/badger_2.png)

This document is a working draft describing a method for servers to authenticate
clients independently using a public key store as authority.

For an explanation of what Badger does in plain English, skip to
[The Party](#the-party-an-analogy-in-plain-english).

Authors
=======

Originally authored by John Driscoll.

Technical consulting by Matthew Brooks.


Motivations
===========

Badger is an alternative to existing decentralized authentication systems that
require regular, direct communication between client and authority.  Badger
allows clients to authenticate with servers easily and securely in a browserless
environment, because there is no necessity to tunnel the client to an authority
for the purposes of its own authentication.  Using Badger, clients need only
communicate with an authority once in their lifetime.

The mechanisms of storage and transfer are not in the scope of this system,
however the example binary (in development) will support the
[Namecoin blockchain](http://dot-bit.org/Main_Page) as an authority.  Namecoin
is an ideal authority because...

* ...it is public.

* ...it is open source.

* ...it is (nearly) impossible to censor.

* ...it is persistent and will never be unavailable due to service outages or
  company bankruptcy.

* ...its records are distributed and cannot be controled or tampered with by any
  one organization or government.

It is worth noting that, while existing decentralized authentication systems do
not necessarily specify a browser requirement, the requirement to tunnel clients
to an authority for authentication directly is universally fulfilled via the
browser.


Terms Used
==========

Term         | Definition
-------------|------------------------------------------------------------------
Client       | A person who wants to be uniquely identified at a server.
Server       | A gathering requiring uniquely identifiable persons.
Authority    | A storage area where Identity URLs are mapped to client records.
Identity URL | A URL resolving to a client's record.
Record       | A publically available object that contains a DSA public key.
Token        | A unique piece of data issued by a server as a client invitation.
Signature    | A client's DSA signature of a token.
Badge        | A client-composed identity that servers can independently verify.

Other references:

* [Digital Signing Algorithm (DSA)]
  (https://en.wikipedia.org/wiki/Digital_Signature_Algorithm)

* [Public Key Cryptography]
  (http://en.wikipedia.org/wiki/Public-key_cryptography)


Timeline
========

First, a client who wants to be uniquely identifiable generates a DSA key pair.
The client keeps her private key private, and posts the public key at some 
public URL in the form of a record.

A server generates unique invitation tokens for distribution to clients.  The
method of delivery is unspecified, but for security purposes, it is recommended
that an invitation be generated and delivered to a client immediately after the
client has initiated communication with, or has otherwise demonstrated intent to
join, the server.

After receiving a token, a client uses her secret key to construct her own
signature of the token.  The client includes her Identity URL, the original
token, and the signature together in a messgae -- her badge -- and sends this
to server.

After receiving a badge, the server should verify that it issued the enclosed
token.  The server then retrieves the client's record at the given Identity URL
and uses it to verify the signature.


Data Specification
==================

    Badge
    ----------------------------------------------------------------------------
    
    JSON object containing the string attributes:
    "id":         Valid Identity URL.
    "token":      Base64-encoded token.
    "signature":  Base64-encoded signature.

    A badge must not include any other attributes.
    
    
    Token
    ----------------------------------------------------------------------------
    
    A token can be any unique data.  A hashed value is recommended.  A raw token
    must be base64-encoded when included as part of a badge.  When authenticat-
    ing a client badge, the raw (base64-decoded) token must be verified with the
    raw (base64-decoded) signature.
    
    
    Signature
    ----------------------------------------------------------------------------
    
    A DSA signature of the raw (base64-decoded) token.  A raw signature must be
    base64-encoded when included as part of a badge.  When authenticating a
    client badge, the raw (base64-decoded) signature must be verified with the
    raw (base64-decoded) token.
    
    
    Record
    ----------------------------------------------------------------------------

    JSON object containing the string attribute:
    "dsa": Base64-encoded public DSA key.

    A record may include any other attributes.
    
    
    Raw DSA Public Key
    ----------------------------------------------------------------------------
    
    DSAPublicKey ::= SEQUENCE {
        publicFlags  BIT STRING(0), -- must be 0
        g            INTEGER      , -- base generator
                                    -- check that g^q mod p == 1
                                    -- and that 1 < g < p - 1
        p            INTEGER      , -- prime modulus
        q            INTEGER      , -- order of sub-group
                                    -- (must be prime)
        y            INTEGER      , -- public key, specifically,
                                    -- g^x mod p,
                                    -- check that y^q mod p == 1
                                    -- and that 1 < y < p - 1
    }


    Raw DSA Private Key
    ----------------------------------------------------------------------------

    DSAPrivateKey ::= SEQUENCE {
        publicFlags  BIT STRING(0), -- must be 1
        g            INTEGER      , -- base generator
                                    -- check that g^q mod p == 1
                                    -- and that 1 < g < p - 1
        p            INTEGER      , -- prime modulus
        q            INTEGER      , -- order of sub-group
                                    -- (must be prime)
        y            INTEGER      , -- public key, specifically,
                                    -- g^x mod p,
                                    -- check that y^q mod p == 1
                                    -- and that 1 < y < p - 1
        x            INTEGER        -- private key
    }

The format of raw DSA public and private keys is taken from the
[libtomcrypt manual](https://libtomcrypt-cug.googlecode.com/files/crypt.pdf).


The Party: An Analogy in Plain English
======================================

Bob wants to throw a party.  At his party, Bob wants everyone to wear a unique
name tag to ease introductions.  Bob is woefully afraid that social embarassment
might arise if two people have identical name tags.  If he devises the right
system, he can avoid any naming collisions, and be able to use the name tags as
the primary form of identifying his guests during the party's events, as every
name tag will be unique.

Bob makes a bunch of invitations, writing a unique message on each.  He makes
a copy of each invitation and keeps the originals for his records.  He then
takes the copies and gives them to his guests, either directly, or by leaving
them in a place where his guests will find them.

Alice, after finding one of Bob's invitations, goes to a "code provider" of her
choice.  Let's say that **Acme** is her choice code provider.  Acme gives Alice
her own special printer, and puts a "public code" for Alice on record.  Alice's
printer is uniquely desgined to print things in a scrambled code.  The scramble
can only be deciphered using the public code that Acme has on record.

Only Alice's Acme printer is able to print Alice's unique scramble.  It will
act as Alice's "private code" that she can use to create badges.  Alice needs
to keep her printer safe and secret because if someone should steal it, they can
print all the "Alice at Acme" badges they want.

Alice feeds the invitation she received into her printer and it prints out a
badge that contains this information:

    Alice at Acme
    Hey Alice, you're invited to Bob's Badge Party!
    Url Nyvpr, lbh'er vaivgrq gb Obo'f Onqtr Cnegl!

This badge will provide Bob with...

1. ...Alice's name and code provider, and...
2. ...the invitation message as originally written by Bob, and...
3. ...the invitation message, but scrambled by the private code in Alice's
   Acme printer.

She brings the badge to the party and gives it to Bob.  Bob recognizes the
invitation he gave to Alice.  Bob calls up Acme and gets Alice's public code.
He then unscrambles the third line of her badge using Alice's public code.
If the third line unscrambles to his original invitation message, he knows
Alice is really **Alice at Acme** because:

* ...he knows only Alice could have created the scrambled invitation using her
  own private code, and...

* ...he knows Acme's public code for Alice is the only way to decipher the
  scramble in Alice's badge to his original invitation message, and...

* ...he knows he issued the invitation, for which he has the original on file.

While there may be more than one Alice at the party, and more than one person
using Acme as their code provider, there can only be one **Alice at Acme**.

Bob can repeat his verification process using any other public code provider his
guest prefers.  No one at Bob's party gets identities confused, and the party is
a rousing success.

Alice, now having a public code on record, can use the same badge printer to get
into any other party she receives an invitation to.


Blind Signing Attacks
=====================

The DSA key must never be used to encrypt a message.  An encrypted message
can be passed to the client as the server token, tricking the client into
[decrypting sensitive information]
(http://en.wikipedia.org/wiki/Blind_signature#Dangers_of_blind_signing).
