<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WARNING! Your web browser does not support window.crypto (required by OpenPGP.js)';

// key manager
$labels['action'] = 'Aktion';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Bit';
$labels['delete'] = 'löschen';
$labels['delete_priv'] = 'Diesen privaten Schlüssel wirklich entfernen?';
$labels['delete_pub'] = 'Diesen öffentlichen Schlüssel wirklich entfernen?';
$labels['fingerprint'] = 'Fingerabdruck';
$labels['generate'] = 'erzeugen';
$labels['generate_keys'] = 'Schlüsselpaar erzeugen';
$labels['ident'] = 'Identität';
$labels['import_completed'] = 'Import completed';
$labels['import_failed'] = 'Konnte Schlüssel nicht importieren, vermutlich falsches Format.';
$labels['import_fail'] = 'Import fehlgeschlagen';
$labels['import_gen'] = 'Vorgang erfolgreich abgeschlossen! Den privaten Schlüssel bitte an einem sicheren Ort aufbewahren und vor Fremdzugriff schützen. Der Schlüssel wird NICHT auf den Server übertragen und steht nur in diesem Browser zur Verfügung!';
$labels['import'] = 'importieren';
$labels['import_private'] = 'privaten Schlüssel importieren';
$labels['import_public'] = 'öffentlichen Schlüssel importieren';
$labels['invalid'] = 'fehlerhaft';
$labels['key_generation_failed'] = 'Key generation failed';
$labels['key_generation_completed'] = 'Key generation completed';
$labels['key_id'] = 'Schlüssel-ID';
$labels['key_manager'] = 'Schlüsselverwaltung';
$labels['key_search'] = 'Schlüsselsuche';
$labels['length_alg'] = 'Länge/Algorithmus';
$labels['pass_mismatch'] = 'Kennwörter stimmen nicht überein';
$labels['person'] = 'Person';
$labels['private_keys'] = 'Privater Schlüssel';
$labels['pubkey_import_success'] = 'Öffentlicher Schlüssel erfolgreich importiert';
$labels['public_keys'] = 'Öffentlicher Schlüssel';
$labels['search_description'] = 'Über diese Suchfunktion können öffentliche Schlüssel gesucht und in die lokale Schlüsselverwaltung importiert werden.';
$labels['search_no_keys'] = 'Es wurden keine zur Suchanfrage passenden Schlüssel gefunden.';
$labels['status'] = 'Status';
$labels['valid'] = 'Gültig';
$labels['verify'] = 'Überprüfen';

// key select
$labels['incorrect_pass'] = 'Passwort falsch';
$labels['none'] = 'Keines';
$labels['selected'] = 'Ausgewählt';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'E-Mails immer verschlüsseln';
$labels['always_sign'] = 'E-Mails immer signieren';
$labels['attach_public_key'] = 'Automatically attach public key';
$labels['openpgp'] = 'OpenPGP';
$labels['sks_key_server'] = 'SKS keyserver';
$labels['sks_key_port'] = 'SKS keyserver port';
$labels['use_hkps'] = 'Keyserver supports HKPS';
$labels['hkps_cert'] = 'CA certificate for HKPS';
$labels['warn_on_unencrypted'] = 'Warn on sending an unencrypted message';

// compose
$labels['continue_unencrypted'] = 'Diese E-Mail wirklich unverschlüsselt und unsigniert versenden?';
$labels['encrypt'] = 'Verschlüsseln';
$labels['encrypting_failed'] = 'Encrypting message failed';
$labels['encrypting_message'] = 'Encrypting message';
$labels['enter_pass'] = 'Bitte Kennwort eingeben';
$labels['message_encrypted'] = 'Message encrypted';
$labels['message_signed'] = 'Message signed';
$labels['message_signed_and_encrypted'] = 'Message signed and encrypted';
$labels['no_keys'] = 'Bitte zuerst über die Schlüsselverwaltung Schlüssel importieren oder erzeugen!';
$labels['save_draft_confirm'] = 'Verschlüselung ist aktiviert. Soll diese E-Mail wirklich als Entwurf gespeichert werden? Hiermit wird eine unverschlüsselte Kopie auf dem Server abgelegt.';
$labels['sign'] = 'Signieren';
$labels['signing_and_encrypting_failed'] = 'Signing and encrypting message failed';
$labels['signing_and_encrypting_message'] = 'Signing and encrypting message';
$labels['signing_failed'] = 'Signing message failed';
$labels['signing_message'] = 'Signing message';

// passphrase
$labels['passphrase'] = 'Kennwort';
$labels['missing_passphrase'] = 'Missing passphrase';
$labels['remember_this_session'] = 'Für diese Sitzung speichern';
$labels['select_key'] = 'Schlüssel auswählen';

// show and preview
$labels['key_mismatch'] = 'Die Nachricht passt nicht zu diesem privaten Schlüssel.';
$labels['message_decrypted'] = 'Message decrypted';
$labels['decrypting_message'] = 'Decrypting message';
$labels['no_key_imported'] = 'Verschlüsselter Inhalt erkannt, aber kein privater Schlüssel vorhanden, diesen bitte über die Schlüsselverwaltung importieren.';
$labels['signature_invalid_sender'] = 'Signatur konnte nicht überprüft werden: keine gültige Absenderadresse erkannt.';
$labels['signature_invalid_no_pubkey'] = 'Signatur konnte nicht überprüft werden: kein öffentlicher Schlüssel gefunden für ';
$labels['signature_invalid'] = 'ACHTUNG: ungültige Signatur';
$labels['signature_valid'] = 'Signatur gültig';
