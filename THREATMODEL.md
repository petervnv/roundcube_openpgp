# Roundcube OpenPGP Threat Model

This threat model is defined in terms of what each possible attacker can achieve (attacker-centric).

## Assumptions:
### User:
* The user acts reasonably and in good faith.
* The user obtains an authentic copy of oundcube OpenPGP.
* The user controls the private key portion of used public-private key pair(s).

### Client:
* The client correctly executes the program and is not compromised by malware.

### Server:
* The server correctly executes the program and is not compromised by malware.

### World:
* The security assumptions of OpenPGP (RFC 4880) are valid.

## Possible attackers:
### What a compromise of the user's Roundcube account can achieve:
* Attacker can obtain any unencrypted drafts.
* Attacker can learn user is using PGP.
* Attacker can learn how many encrypted messages a user receives, who sends them, when they are sent, where they are sent from (if geolocation based on IP address is possible), when the user receives them and when they are marked, moved to a folder or deleted.
* Attacker can learn how many encrypted messages a user sends, where they are sent from (if $rcmail_config['http_received_header']==true and geolocation based on IP address is possible), whom they are sent to and when they are sent.
* Attacker can learn which IMAP folder encrypted messages are moved to and whether they are deleted, marked as read or important etc.
* Attacker can learn the size of any sent or received encrypted message.
* Attacker can delete or replace any encrypted message.
* Attacker can read the subject line and headers of encrypted messages.

### What the server can achieve:
* A server can learn user is using PGP.
* A server can learn how many encrypted messages a user receives, who sends them, when they are sent, where they are sent from (if geolocation based on IP address is possible), when the user receives them and when they are marked, moved to a folder or deleted.
* A server can learn how many encrypted messages a user sends, whom they are sent to and when they are sent.
* A server can learn which IMAP folder encrypted messages are moved to and whether they are deleted, marked as read or important etc.
* A server can learn the size of any sent or received encrypted message.
* A server can drop or corrupt any encrypted messages.
* A server can strip the signature from any signed message.
* A server can learn any unencrypted drafts.
* A server can read the subject line and headers of encrypted messages.
* A server can learn the user's location if geolocation based on IP address is possible.
* A server can learn the user's IMAP credentials -- in that case, all points from "What a compromise of the user's Roundcube account can achieve" apply.
* A web server can output malicious JavaScript code to the user's browser in order to transmit arbitrary client data back to the server. See "What a physical compromise of the user's client can achieve".

### What a global passive adversary (GPA) can achieve:
* A GPA can learn who is using PGP.
* A GPA can learn how many encrypted messages a user receives, who sends them, when they are sent, where they are sent from (if geolocation based on IP address is possible) and when the user receives them.
* A GPA can learn how many encrypted messages a user sends, where they are sent from (if $rcmail_config['http_received_header']==true and geolocation based on IP address is possible), whom they are sent to and when they are sent.
* A GPA can learn the size of any sent or received encrypted message.
* A GPA can read the subject line and headers of encrypted messages.
* If there is no transport security between client and server or if transport security is compromised (server's private key in attacker's possession and no PFS enabled), most points from "What a compromise of the user's Roundcube account can achieve" and many points from "What the server can achieve" apply here as well.

### What a physical seizure of the user's client can achieve:
* Attacker can obtain user's private key and encrypt, sign and decrypt user messages if passphrase is known (or successful attack against the passphrase).
* Attacker can make assumptions as to whom the user has corresponded with, based on the list of public keys.

### What a physical compromise of the user's client can achieve:
* Attacker can obtain all encrypted messages and decrypt from the point of compromise if passphrase is known (or successful attack against the passphrase).
* Attacker can obtain user's private key(s) and sign messages if passphrase is known (or successful attack against the passphrase).
* Attacker can intercept and manipulate all traffic to and from the server from the point of compromise.
* Attacker can gain permanent access to the user's Roundcube account by sniffing user credentials unless the user is employing one-time pads.
* Attacker can read decrypted messages from the point of compromise, e.g. via man-in-the-browser attacks or spyware (screen dumps).
* Attacker can obtain passphrases via keylogging or man-in-the-browser attacks.
* Attacker can add, delete or replace public keys.
* Attacker can make assumptions as to whom the user has corresponded with, based on the list of public keys.
