<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WARNING! Your web browser does not support window.crypto (required by OpenPGP.js)';

// key manager
$labels['action'] = 'Action';
$labels['bits'] = 'Bitar';
$labels['delete'] = 'Radera';
$labels['delete_priv'] = 'Radera privat nyckel?';
$labels['delete_pub'] = 'Radera publik nyckel?';
$labels['fingerprint'] = 'Fingerprint';
$labels['generate'] = 'Generera';
$labels['generate_keys'] = 'Generera nycklar';
$labels['ident'] = 'Identitet';
$labels['import_failed'] = 'Det gick inte att importera nyckel, eventuellt fel format';
$labels['import_fail'] = 'Kunde inte importera';
$labels['import_gen'] = 'Spara din privata nyckel säkert någonstans, förslagsvis i en krypterad container. Din privata nyckel överförs inte till mailservern.';
$labels['import'] = 'Importera';
$labels['import_private'] = 'Importera privat nyckel';
$labels['import_public'] = 'Importera publik nyckel';
$labels['invalid'] = 'Ogiltig';
$labels['key_id'] = 'Nyckel-ID';
$labels['key_manager'] = 'Nyckelhanterare';
$labels['key_search'] = 'Sök nyckel';
$labels['length_alg'] = 'Längd/algoritm';
$labels['pass_mismatch'] = 'Passphrase mismatch';
$labels['person'] = 'Person';
$labels['private_keys'] = 'Privata nycklar';
$labels['pubkey_import_success'] = 'Lyckades importera den publika nyckeln';
$labels['public_keys'] = 'Publika nycklar';
$labels['search_description'] = 'Use this search to find and import public keys into your local key manager.';
$labels['search_no_keys'] = 'No keys matched your search, try another query.';
$labels['status'] = 'Status';
$labels['valid'] = 'Giltig';
$labels['verify'] = 'Verifiera';
$labels['incorrect_pass'] = 'Fel lösenord';
$labels['none'] = 'inga';
$labels['selected'] = 'Vald';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Kryptera alltid';
$labels['always_sign'] = 'Signera alltid';
$labels['openpgp_options'] = 'OpenPGP Inställningar';

// compose
$labels['continue_unencrypted'] = 'Fortsätt skicka okrypterad och osignerad data?';
$labels['encrypt'] = 'Kryptera';
$labels['enter_pass'] = 'Ange lösenord';
$labels['no_keys'] = 'Please generate or import keys in the key manager!';
$labels['save_draft_confirm'] = 'Encryption is enabled, are you sure that you want to save this draft? By doing so you save an unencrypted copy on the server.';
$labels['sign'] = 'Signera';

// passphrase
$labels['passphrase'] = 'Lösenordsfras';
$labels['remember_this_session'] = 'Kom ihåg under denna session';
$labels['select_key'] = 'Välj nyckel';

// show and preview
$labels['key_mismatch'] = 'Fel nyckel för detta meddelande';
$labels['no_key_imported'] = 'Detected PGP encrypted content but no imported private keys. Please import your private PGP key using the key manager!';
$labels['signature_invalid_sender'] = 'Could not verify signature: No valid sender email address recognized';
$labels['signature_invalid_no_pubkey'] = 'Could not verify signature: No public key found for ';
$labels['signature_invalid'] = 'CAUTION: Invalid signature';
$labels['signature_valid'] = 'Signature valid';
