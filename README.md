Badger
======

This document is a working draft describing a system for the creation and
verification of unique identities using a public key store as authority.
The mechanisms of storage and transfer are not in the scope of this system,
however the example library (in development) will use the
[Namecoin blockchain](http://dot-bit.org/Main_Page) for key retrieval.


Authors
=======

Originally authored by John Driscoll.

Technical consulting by Matthew Brooks.


The Party
=========

Bob wants to throw a party.  At his party, Bob wants everyone to wear a unique name
tag to ease introductions.  Bob is woefully afraid that social embarassment might
arise if two people have identical name tags.  If he devises the right system, he
can avoid any naming collisions, and be able to use the name tags as the primary mode
of identifying his guests during the party's events, as every name tag will be unique.

Bob makes a bunch of invitations, writing a unique message on each.  He makes
a copy of each invitation and keeps the originals for his records.  He then takes
the copies and gives them to his guests, either directly, or by leaving them in a place
where his guests will find them.

Alice, after finding one of Bob's invitations, goes to a key provider of her choice.
Let's say that Namecoin(tm) is her choice key provider.  Namecoin(tm) gives Alice
her own special printer, and puts a "public key" for Alice on record.
Alice's printer is uniquely designed to print in a secret code that can only be
translated using the public key Namecoin(tm) puts on record.

Only Alice's Namecoin(tm) printer is able to print things using Alice's secret code.
It will act as Alice's "private key" that she can use to create badges.  Alice needs
to keep her printer safe and secret because if someone should steal it, they can
print all the "Alice at Namecoin(tm)" badges they want.

Alice feeds the invitation she received into her printer and it prints out a badge
that looks something like this:

    Alice at Namecoin(tm)
    Hey Alice, you're invited to Bob's Badge Party!
    MEECHwDC6SwOPmsH5wiGOwFS0tldxGHrhYBuIrFSPAF+xAYCHmIU==

The first line identifies who the badge (and invitation) belong to.
The second line is the invitation message as originally written by Bob.
The third line is the invitation message, scrambled by the private key in
Alice's printer.

She brings the badge to the party and gives it to Bob.  Bob recognizes the invitation
he gave to Alice.  Bob calls up Namecoin(tm) and gets Alice's public key.  He then
unscrambles the third line of her badge using Alice's public key.  If the third line
unscrambles to his original invitation message, he will let Alice in, because...

  * ...he knows only Alice could have created the scrambled message using her own
    private key, and...

  * ...he knows Namecoin(tm)'s public key for Alice is the only way to unscramble
    the secret code in Alice's badge to his original invitation message, and...

  * ...he knows he issued the invitation, for which he has the original on file, and...

  * ...he knows there may be more than one Alice at the party, and more than one
    person using Namecoin(tm) as their key provider, but there can only be one
    "Alice at Namecoin(tm)".
  
Bob can repeat his verification process using any other public key provider his
guest prefers.  No one at Bob's party gets identities confused, and the party is
a rousing success.

Alice, now having a public key on record, can use the same badge printer to get into
any other party she receives an invitation to.


Terms Used
==========

**Client**:
Someone who wants to be uniquely identified at a server.  Alice is the client in
the party analogy.

**Server**:
A gathering requiring uniquely identifiable guests.  Bob is the server in the party
analogy.

**Public key store**:
Some publically available storage mechanism that maps names to public DSA keys.

**Identity URI**:
A client's "name", for verification purposes.  This URI must resolve to the client's
public DSA key.

**Token**: 
A unique piece of data issued by the server as an invitation to clients.

**Signature**:
A scrambled form of a token that is produced using a client's secret key.

**Badge**:
A message from client to server containing the client's identity URI, token, and
signature.


Data Specification
==================

**Badge**:

    < Identity URI >
    < Base64-encoded token >
    < Base64-encoded signature >

*Note*: Each component string of a badge is delimited with a newline character.


Timeline
========

It begins with the server generating a unique invitation token for distribution to
clients.  The method of delivery is unspecified, but for security purposes, it is
recommended that an invitation be generated and delivered to a client immediately
after the client has initiated communication with, or has otherwise demonstrated
intent to join, the server.  The longer a token is, the more entropy it contains,
the better it is for the server's integrity.

After receiving a token, a client uses her secret key to construct their own
signature of the token.  The client includes her identity URI, the original token,
and the signature together in a messgae -- her badge -- and sends this to server.

After receiving a badge, the server retrieves the client's public DSA key at the
given identity URI and uses it to verify that the token signature came from the
client.
