<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WARNING! Your web browser does not support window.crypto (required by OpenPGP.js)';

// key manager
$labels['action'] = 'Actie';
$labels['bits'] = 'Bits';
$labels['delete'] = 'Verwijder';
$labels['delete_priv'] = 'Verwijder deze geheime sleutel?';
$labels['delete_pub'] = 'Verwijder deze publieke sleutel?';
$labels['fingerprint'] = 'Vingerafdruk';
$labels['generate'] = 'Genereer';
$labels['generate_keys'] = 'Genereer sleutels';
$labels['ident'] = 'Identiteit';
$labels['import_failed'] = 'Kan sleutel niet importeren, mogelijk verkeerd formaat';
$labels['import_fail'] = 'Importeren mislukt';
$labels['import_gen'] = 'Groot success! Bewaar je sleutels ergens veilig, bij voorkeur in een versleutelde container. Sleutels zijn niet verzonden naar de server.';
$labels['import'] = 'Importeer';
$labels['import_private'] = 'Importeer geheime sleutel';
$labels['import_public'] = 'Importeer publieke sleutel';
$labels['invalid'] = 'Ongeldig';
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
$labels['incorrect_pass'] = 'Incorrect wachtwoord';
$labels['none'] = 'geen';
$labels['selected'] = 'Geselecteerd';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Berichten altijd versleutelen';
$labels['always_sign'] = 'Berichten altijd signeren';
$labels['openpgp_options'] = 'OpenPGP Opties';

// compose
$labels['continue_unencrypted'] = 'Niet versleutelde of gesigneerde mail versturen?';
$labels['encrypt'] = 'Versleutel';
$labels['enter_pass'] = 'Geef een wachtwoord op';
$labels['no_keys'] = 'Genereer of importeer sleutels in sleutel beheer!';
$labels['save_draft_confirm'] = 'Versleuteling is ingeschakeld, weet je zeker dat je dit concept wil opslaan? Hierdoor wordt er een onversleutelde kopie opgeslagen op de server.';
$labels['sign'] = 'Signeer';

// passphrase
$labels['passphrase'] = 'Wachtwoord';
$labels['remember_this_session'] = 'Onthoud voor deze sessie';
$labels['select_key'] = 'Selecteer sleutel';

// show and preview
$labels['key_mismatch'] = 'Dit bericht was niet bedoeld voor deze geheime sleutel';
$labels['no_key_imported'] = 'PGP versleutelde inhoud gevonden, maar er zijn geen geheime sleutels geimporteerd. Importeer je geheime sleutels via Sleutel beheer!';
$labels['signature_invalid_sender'] = 'Could not verify signature: No valid sender email address recognized';
$labels['signature_invalid_no_pubkey'] = 'Could not verify signature: No public key found for ';
$labels['signature_invalid'] = 'CAUTION: Invalid signature';
$labels['signature_valid'] = 'Signature valid';
