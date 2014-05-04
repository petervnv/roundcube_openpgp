<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WAARSCHUWING! Je webbrowser ondersteund geen window.crypto (vereist voor OpenPGP.js)';

// key manager
$labels['action'] = 'Actie';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Bits';
$labels['delete'] = 'Verwijder';
$labels['delete_priv'] = 'Verwijder deze geheime sleutel?';
$labels['delete_pub'] = 'Verwijder deze publieke sleutel?';
$labels['fingerprint'] = 'Vingerafdruk';
$labels['generate'] = 'Genereer';
$labels['generate_keys'] = 'Genereer sleutels';
$labels['ident'] = 'Identiteit';
$labels['import_completed'] = 'Importeren voltooid';
$labels['import_failed'] = 'Kan sleutel niet importeren, mogelijk verkeerd formaat';
$labels['import_fail'] = 'Importeren mislukt';
$labels['import_gen'] = 'Groot success! Bewaar je sleutels ergens veilig, bij voorkeur in een versleutelde container. Sleutels zijn niet verzonden naar de server.';
$labels['import'] = 'Importeer';
$labels['import_private'] = 'Importeer geheime sleutel';
$labels['import_public'] = 'Importeer publieke sleutel';
$labels['invalid'] = 'Ongeldig';
$labels['key_generation_failed'] = 'Sleutel generatie mislukt';
$labels['key_generation_completed'] = 'Sleutel generatie voltooid';
$labels['key_id'] = 'Sleutel ID';
$labels['key_manager'] = 'Sleutel beheer';
$labels['key_search'] = 'Sleutel zoeken';
$labels['length_alg'] = 'Lengte/Alg';
$labels['pass_mismatch'] = 'Wachtwoorden komen niet overeen';
$labels['person'] = 'Persoon';
$labels['private_keys'] = 'Geheime sleutels';
$labels['pubkey_import_success'] = 'Publieke sleutel is geimporteerd';
$labels['public_keys'] = 'Publieke sleutels';
$labels['search_description'] = 'Gebruik deze zoekfunctie om publieke sleutels te vinden en te importeren in je lokale sleutel beheer.';
$labels['search_no_keys'] = 'No keys matched your search, try another query.';
$labels['status'] = 'Status';
$labels['valid'] = 'Geldig';
$labels['verify'] = 'Verifieer';

// key select
$labels['incorrect_pass'] = 'Incorrect wachtwoord';
$labels['none'] = 'geen';
$labels['selected'] = 'Geselecteerd';
$labels['key_select'] = 'Selecteer sleutel';

// settings
$labels['always_encrypt'] = 'Berichten altijd versleutelen';
$labels['always_sign'] = 'Berichten altijd signeren';
$labels['attach_public_key'] = 'Automatically attach public key';
$labels['openpgp'] = 'OpenPGP';
$labels['warn_on_unencrypted'] = 'Warn on sending an unencrypted message';

// compose
$labels['continue_unencrypted'] = 'Niet versleutelde of gesigneerde mail versturen?';
$labels['encrypt'] = 'Versleutel';
$labels['encrypting_failed'] = 'Versleutelen bericht mislukt';
$labels['encrypting_message'] = 'Bericht versleutelen';
$labels['enter_pass'] = 'Geef een wachtwoord op';
$labels['message_encrypted'] = 'Bericht versleuteld';
$labels['message_signed'] = 'Bericht ondertekend';
$labels['message_signed_and_encrypted'] = 'Bericht ondertekend en versleuteld';
$labels['no_keys'] = 'Genereer of importeer sleutels in sleutel beheer!';
$labels['save_draft_confirm'] = 'Versleuteling is ingeschakeld, weet je zeker dat je dit concept wil opslaan? Hierdoor wordt er een onversleutelde kopie opgeslagen op de server.';
$labels['sign'] = 'Signeer';
$labels['signing_and_encrypting_failed'] = 'Ondertekenen en versleutelen bericht mislukt';
$labels['signing_and_encrypting_message'] = 'Ondertekenen en versleutelen bericht';
$labels['signing_failed'] = 'Ondertekenen bericht mislukt';
$labels['signing_message'] = 'Ondertekenen bericht';

// passphrase
$labels['passphrase'] = 'Wachtwoord';
$labels['missing_passphrase'] = 'Ontbrekend wachtwoord';
$labels['remember_this_session'] = 'Onthoud voor deze sessie';
$labels['select_key'] = 'Selecteer sleutel';

// show and preview
$labels['key_mismatch'] = 'Dit bericht was niet bedoeld voor deze geheime sleutel';
$labels['message_decrypted'] = 'Message decrypted';
$labels['decrypting_message'] = 'Decrypting message';
$labels['no_key_imported'] = 'PGP versleutelde inhoud gevonden, maar er zijn geen geheime sleutels geimporteerd. Importeer je geheime sleutels via Sleutel beheer!';
$labels['signature_invalid_sender'] = 'Could not verify signature: No valid sender email address recognized';
$labels['signature_invalid_no_pubkey'] = 'Could not verify signature: No public key found for ';
$labels['signature_invalid'] = 'WAARSCHUWING: Ongeldige handtekening';
$labels['signature_valid'] = 'Handtekening geldig';
