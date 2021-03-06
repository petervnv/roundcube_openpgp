<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WARNING! Your web browser does not support window.crypto (required by OpenPGP.js)';

// key manager
$labels['action'] = 'Action';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Bits';
$labels['creation'] = 'Creation';
$labels['delete'] = 'Delete';
$labels['delete_priv'] = 'Delete this private key?';
$labels['delete_pub'] = 'Delete this public key?';
$labels['expiration'] = 'Expiration';
$labels['export_complete'] = 'Exporting keys is completed';
$labels['export_failed'] = 'Exporting keys failed';
$labels['export_keys'] = 'Export keys';
$labels['export_keys_desc'] = 'Please save your exported (private) keys somewhere safe, preferably in an encrypted container.';
$labels['fingerprint'] = 'Fingerprint';
$labels['generate'] = 'Generate';
$labels['generate_keys'] = 'Generate key pair';
$labels['ident'] = 'Identity';
$labels['import_completed'] = 'Import completed';
$labels['import_failed'] = 'Could not import key, possibly wrong format';
$labels['import_gen'] = 'Import completed. Save your private key safe, it is not stored on the server.';
$labels['import'] = 'Import';
$labels['import_keys'] = 'Import keys';
$labels['import_keys_desc'] = 'Import multiple keys by pasting them below.';
$labels['import_private'] = 'Imported private key for';
$labels['import_public'] = 'Imported public key for';
$labels['invalid'] = 'Invalid';
$labels['key_generation_failed'] = 'Key generation failed';
$labels['key_generation_completed'] = 'Key generation completed';
$labels['key_id'] = 'Key ID';
$labels['key_manager'] = 'Key manager';
$labels['key_search'] = 'Key search';
$labels['length_alg'] = 'Length/Alg';
$labels['no_expiration'] = 'Does not expire';
$labels['pass_mismatch'] = 'Passphrases don\'t match';
$labels['paste_keys'] = 'Paste keys to import here...';
$labels['person'] = 'Person';
$labels['private_keys'] = 'Private keys';
$labels['pubkey_import_success'] = 'Public key imported successfully';
$labels['public_keys'] = 'Public keys';
$labels['revoked'] = 'Revoked';
$labels['search_description'] = 'Use this search to find and import public keys into your local key manager.';
$labels['search_no_keys'] = 'No keys matched your search, try another query.';
$labels['status'] = 'Status';
$labels['valid'] = 'Valid';
$labels['verify'] = 'Verify';

// key select
$labels['incorrect_pass'] = 'Incorrect passphrase';
$labels['none'] = 'none';
$labels['selected'] = 'Selected';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Always encrypt messages';
$labels['always_sign'] = 'Always sign messages';
$labels['attach_public_key'] = 'Automatically attach public key';
$labels['openpgp'] = 'OpenPGP';
$labels['sks_key_server'] = 'SKS keyserver';
$labels['sks_key_port'] = 'SKS keyserver port';
$labels['use_hkps'] = 'Keyserver supports HKPS';
$labels['hkps_cert'] = 'CA certificate for HKPS';
$labels['warn_on_unencrypted'] = 'Warn on sending an unencrypted message';

// compose
$labels['continue_unencrypted'] = 'Continue sending unencrypted and unsigned email?';
$labels['encrypt'] = 'Encrypt';
$labels['encrypting_failed'] = 'Encrypting message failed';
$labels['encrypting_message'] = 'Encrypting message';
$labels['message_encrypted'] = 'Message encrypted';
$labels['message_signed'] = 'Message signed';
$labels['message_signed_and_encrypted'] = 'Message signed and encrypted';
$labels['no_keys'] = 'Please generate or import keys in the key manager!';
$labels['save_draft_confirm'] = 'Encryption is enabled, are you sure that you want to save this draft? By doing so you save an unencrypted copy on the server.';
$labels['sign'] = 'Sign';
$labels['signing_and_encrypting_failed'] = 'Signing and encrypting message failed';
$labels['signing_and_encrypting_message'] = 'Signing and encrypting message';
$labels['signing_failed'] = 'Signing message failed';
$labels['signing_message'] = 'Signing message';

// passphrase
$labels['passphrase'] = 'Passphrase';
$labels['missing_passphrase'] = 'Missing passphrase';
$labels['remember_this_session'] = 'Remember for this session';
$labels['select_key'] = 'Please select a key';

// show and preview
$labels['key_mismatch'] = 'This message was not intended for this private key';
$labels['message_decrypted'] = 'Message decrypted';
$labels['decrypting_message'] = 'Decrypting message';
$labels['no_key_imported'] = 'Detected PGP encrypted content but no imported private keys. Please import your private PGP key using the key manager!';
$labels['signature_invalid_sender'] = 'Could not verify signature: No valid sender email address recognized';
$labels['signature_invalid_no_pubkey'] = 'Could not verify signature: No public key found for ';
$labels['signature_invalid'] = 'CAUTION: Invalid signature';
$labels['signature_valid'] = 'Signature valid';
