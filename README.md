Roundcube OpenPGP
=================

Attention
---------
Please don't use this plugin for anything real yet, it has never been reviewed. 
Unless you're experimenting you should use something that works and has been reviewed.
Also read [What’s wrong with in-browser cryptography?][wrong]

Introduction
------------
Roundcube OpenPGP is an open source (GPLv2) extension adding OpenPGP support
to the Roundcube webmail project. Roundcube OpenPGP is written with the intention to
be as user friendly as possible for everyday PGP use. See
[Why do you need PGP?][why], [OpenPGP.js][openpgpjs] and [Roundcube][roundcube]
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
2. Add 'rc_openpgpjs' to the $config['plugins'] array in your Roundcube config (config/config.inc.php)

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
[issues]: https://github.com/lazlolazlolazlo/rc_openpgpjs/issues
[wrong]: http://tonyarcieri.com/whats-wrong-with-webcrypto
[why]: http://www.pgpi.org/doc/whypgp/en/
[draft]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
