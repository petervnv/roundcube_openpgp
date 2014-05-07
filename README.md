Roundcube OpenPGP
=================

Attention
---------
Please __don't__ use this plugin for anything real yet, it has never been reviewed. 
Unless you're experimenting you should use something that _works_ and has been _reviewed_.
Also read [What’s wrong with in-browser cryptography?][wrong] and [Javascript Cryptography Considered Harmful][harmful].

Introduction
------------
Roundcube OpenPGP is an open source (GPLv2) extension adding OpenPGP support
to the Roundcube webmail project. Roundcube OpenPGP is written with the intention to
be as user friendly as possible for everyday PGP use. See
[Why do you need PGP?][why], [Encrypted email][encrypted], [OpenPGP.js][openpgpjs] and [Roundcube][roundcube]
for more info.

Features
--------
- e-mail OpenPGP signing and verification
- e-mail OpenPGP encryption and decryption
- key storage (HTML5 local storage)
- key pair generation
- key lookups against PGP Secure Key Servers

Installation
------------
1. Copy plugin to 'plugins' folder
2. Add 'roundcube_openpgp' to the $config['plugins'] array in your Roundcube config (config/config.inc.php)
3. Copy 'config.inc.php.dist' to 'config.inc.php' and configure the plugin or keep the defaults

Usage
-----
_Note that in order to use this plugin your browsers needs to support [window.crypto.getRandomValues][random]._

First import your public and private key (if you do not have a key pair, generate one first)

### Sending emails
When sending emails you can choose if you want to sign and / or encrypt the message.
To encrypt a message you have to have the public keys of the receipients of the message in the key mamager.
If this is not the case import them into the key manager or use the key search to import them.
For signing the email your private key is needed, if you have multiple private keys you will be prompted to choose one before sending.

### Receiving emails
For receiving messages it is the other way around, to decrypt an encrypted message you need your private key.
For verifying the signature of the message you need the public key of the sender.

Key storage
-----------
The keys are stored client side using HTML5 local storage.
Private keys are never transferred from the user's local storage.
Private and public keys can be exported from the web storage and be used outside of Roundcube and equally
externally generated keys can be imported and used inside Roundcube.

Key lookups
-----------
Public keys can be imported from PGP Secure Key Servers, i.e. pool.sks-keyservers.net and
any other Public Key Server which follows the [OpenPGP HTTP Keyserver Protocol 
(HKP)][draft], i.e pgp.mit.edu.

Contact
-------
For any bug reports or feature requests please refer to the [tracking system][issues].

[roundcube]: http://www.roundcube.net/
[openpgpjs]: https://openpgpjs.org/
[issues]: https://github.com/lazlolazlolazlo/roundcube_openpgp/issues
[wrong]: http://tonyarcieri.com/whats-wrong-with-webcrypto
[harmful]: http://www.matasano.com/articles/javascript-cryptography/
[why]: http://www.pgpi.org/doc/whypgp/en/
[draft]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
[random]: https://developer.mozilla.org/en-US/docs/Web/API/window.crypto.getRandomValues#Browser_Compatibility
[encrypted]: https://www.riseup.net/en/encrypted-email
