Badger
======

Bob is throwing a hat party where everyone gets their own unique, personalized hat.
He has just enough hats to give one to each guest, so, he needs to be sure that
he doesn't give anyone more than one hat, even though everyone will be trying to
get more than one hat.  But Bob has a plan.

Bob writes down a bunch of invitations with a unique message on each.  The invitation
says that hats will be given out to anyone with a valid badge.  He keeps the originals
for each invitation he writes, and leaves the copies in a place his friends can find them.

Alice, after finding one of Bob's invitations, goes to a key provider of her choice.
Let's say that Namecoin(tm) is her choice key provider.  Namecoin(tm) gives Alice
her own special printer, and puts a "public key" for Alice on record.
Alice's printer is uniquely designed to print in a secret code that can only be
translated using the public key Namecoin(tm) puts on record.

Only Alice's Namecoin(tm) printer is able to print these secret codes. It will act
as Alice's "private key" that she can use to create badges.  Alice needs to keep
her printer safe and secret because if someone should steal it, they can print all
the Alice at Namecoin(tm) badges they want.

Alice feeds Bob's unique hat party invitation into her printer and it prints out
a badge that looks something like this:

    Alice at Namecoin(tm)
    Super Cool Hat Party Invitation! Just Bring A Badge! -Bob
    MEECHwDC6SwOPmsH5wiGOwFS0tldxGHrhYBuIrFSPAF+xAYCHmIU==

The first line identifies who the badge (and invitation) belong to.
The second line is the original invitation message written by Bob.
The third line is the invitation message scrambled using Alice's private key.

She brings the badge to the party and gives it to Bob.  Bob calls up Namecoin(tm)
and gets Alice's public key.  He then unscrambles the third line of her badge using
Alice's public key.  If the third line unscrambles to his original invitation message,
he will give Alice a hat because:

  * ...he knows only Alice could have created that scrambled message using her own
    private key, and...

  * ...he knows Namecoin(tm)'s public key for Alice is the only way to unscramble
    the secret code in Alice's badge, and...

  * ...he knows he issued the original invitations, for which he has a copy of each.
