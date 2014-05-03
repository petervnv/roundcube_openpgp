Roundcube OpenPGP
=================
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

Installation
------------
1. Copy plugin to 'plugins' folder
2. Add 'rc_openpgpjs' to plugins array in your Roundcube config (config/main.inc.php)

Contact
-------
For any bug reports or feature requests please refer to the [tracking system][issues].

Questions? Please see the [FAQ][faq].

[roundcube]: http://www.roundcube.net/
[openpgpjs]: https://openpgpjs.org/
[issues]: https://github.com/lazlolazlolazlo/rc_openpgpjs/issues
[why]: http://www.pgpi.org/doc/whypgp/en/
[draft]: https://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
[faq]: https://github.com/qnrq/rc_openpgpjs/wiki/FAQ
