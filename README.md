Badger
======

This document is a working draft describing a system of verification of unique
identities using a public key store as authority.  The mechanisms of storage and
transfer are not in the scope of this system, however the example binary (in
development) will use the [Namecoin blockchain](http://dot-bit.org/Main_Page)
for key retrieval.


Authors
=======

Originally authored by John Driscoll.

Technical consulting by Matthew Brooks.


The Party
=========

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
badge that looks something like this:

    Alice at Acme
    Hey Alice, you're invited to Bob's Badge Party!
    Url Nyvpr, lbh'er vaivgrq gb Obo'f Onqtr Cnegl!

The first line identifies who the badge (and invitation) belong to.
The second line is the invitation message as originally written by Bob.
The third line is the invitation message, but scrambled by the private code in
Alice's printer.

She brings the badge to the party and gives it to Bob.  Bob recognizes the
invitation he gave to Alice.  Bob calls up Acme and gets Alice's public code.
He then unscrambles the third line of her badge using Alice's public code.
If the third line unscrambles to his original invitation message, he will let
Alice in, because...

  * ...he knows only Alice could have created the scrambled message using her
    own private code, and...

  * ...he knows Acme's public code for Alice is the only way to unscramble
    the secret code in Alice's badge to his original invitation message, and...

  * ...he knows he issued the invitation, for which he has the original on file,
    and...

  * ...he knows there may be more than one Alice at the party, and more than one
    person using Acme as their code provider, but there can only be one
    **Alice at Acme**.
  
Bob can repeat his verification process using any other public code provider his
guest prefers.  No one at Bob's party gets identities confused, and the party is
a rousing success.

Alice, now having a public code on record, can use the same badge printer to get
into any other party she receives an invitation to.


Terms Used
==========


**Client**           | Someone who wants to be uniquely identified at a server.
                     | Alice is the client in the party analogy.
                     |
**Server**           | A gathering requiring uniquely identifiable guests.  Bob
                     | is the server in the party analogy.
                     |
**Public key store** | Some publically available storage mechanism that maps
                     | names to public DSA keys via a URL.
                     |
**Identity URL**     | A client's "name", for verification purposes.  This URL
                     | resolves to the client's public DSA key.
                     |
**Token**            | A unique piece of data issued by the server as an
                     | invitation to clients.
                     |
**Signature**        | DSA signature of a token.
                     |
**Badge**            | A message from client to server containing the client's
                     | identity URL, token, and signature.


Data Specification
==================

**Badge** | A JSON object containing three attributes...


Timeline
========

First, a client who wants to be uniquely identifiable generates a DSA key pair.
The client keeps her private key private, and posts the public key at some 
public URL.  This becomes her identity URL.

A server generates unique invitation tokens for distribution to clients.  The
method of delivery is unspecified, but for security purposes, it is recommended
that an invitation be generated and delivered to a client immediately after the
client has initiated communication with, or has otherwise demonstrated intent to
join, the server.  The longer a token is, the more entropy it contains, the
better it is for the integrity of the server.

After receiving a token, a client uses her secret key to construct her own
signature of the token.  The client includes her identity URL, the original
token, and the signature together in a messgae -- her badge -- and sends this
to server.

After receiving a badge, the server retrieves the client's public DSA key at the
given identity URL and uses it to verify that the token signature.


TODO
====

* Library

* Sample verification binary

* Document conventions ( markdown, 80 char lines, etc. )

* TOC