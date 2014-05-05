<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'ATTENZIONE! Il tuo browser non supporta window.crypto (richiesto da OpenPGP.js)';

// key manager
$labels['action'] = 'Azione';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Bit';
$labels['delete'] = 'Elimina';
$labels['delete_priv'] = 'Eliminare questa chiave privata?';
$labels['delete_pub'] = 'Eliminare questa chiave pubblica?';
$labels['fingerprint'] = 'Fingerprint';
$labels['generate'] = 'Genera';
$labels['generate_keys'] = 'Genera chiavi';
$labels['ident'] = 'Identità';
$labels['import_completed'] = 'Import completed';
$labels['import_failed'] = 'Impossibile importare la chiave, il formato potrebbe essere errato';
$labels['import_fail'] = 'Importazione non riuscita';
$labels['import_gen'] = 'Successo! Salva la tua chiave privata in un posto sicuro, meglio se su un supporto cifrato. La tua chiave proivata non verrà trasferita sul server.';
$labels['import'] = 'Importa';
$labels['import_private'] = 'Importa chiave privata';
$labels['import_public'] = 'Importa chiave pubblica';
$labels['invalid'] = 'Non valida';
$labels['key_generation_failed'] = 'Key generation failed';
$labels['key_generation_completed'] = 'Key generation completed';
$labels['key_id'] = 'Chiave ID';
$labels['key_manager'] = 'Gestore Chiavi';
$labels['key_search'] = 'Cerca chiave';
$labels['length_alg'] = 'Length/Alg';
$labels['pass_mismatch'] = 'La Passphrase non corrisponde';
$labels['person'] = 'Persona';
$labels['private_keys'] = 'Chiavi private';
$labels['pubkey_import_success'] = 'Chiave pubblica importata con successo';
$labels['public_keys'] = 'Chiavi pubbliche';
$labels['search_description'] = 'Usa questa ricerca per trovare ed importare chiavi pubbliche nel tuo Gestore chiavi.';
$labels['search_no_keys'] = 'Nessuna chiave corrisponde alla ricerca.';
$labels['status'] = 'Stato';
$labels['valid'] = 'Valido';
$labels['verify'] = 'Verifica';

// key select
$labels['incorrect_pass'] = 'Passphrase non corretta';
$labels['none'] = 'nessuno';
$labels['selected'] = 'Selezionata';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Cifra sempre i messaggi';
$labels['always_sign'] = 'Firma sempre i messaggi';
$labels['attach_public_key'] = 'Automatically attach public key';
$labels['openpgp'] = 'OpenPGP';
$labels['sks_key_server'] = 'SKS keyserver';
$labels['sks_key_port'] = 'SKS keyserver port';
$labels['use_hkps'] = 'Keyserver supports HKPS';
$labels['hkps_cert'] = 'CA certificate for HKPS';
$labels['warn_on_unencrypted'] = 'Warn on sending an unencrypted message';

// compose
$labels['continue_unencrypted'] = 'Continuare ad inviare la mail non cifrata e non firmata?';
$labels['encrypt'] = 'Cifra';
$labels['encrypting_failed'] = 'Encrypting message failed';
$labels['encrypting_message'] = 'Encrypting message';
$labels['enter_pass'] = 'Inserisci la passphrase';
$labels['message_encrypted'] = 'Message encrypted';
$labels['message_signed'] = 'Message signed';
$labels['message_signed_and_encrypted'] = 'Message signed and encrypted';
$labels['no_keys'] = 'Genera o importa chiavi nel Gestore chiavi!';
$labels['save_draft_confirm'] = 'Cifratura abilitata, sei sicuro di voler salvare questa bozza? Procedendo salverai sul server una copia non cifrata.';
$labels['sign'] = 'Firma';
$labels['signing_and_encrypting_failed'] = 'Signing and encrypting message failed';
$labels['signing_and_encrypting_message'] = 'Signing and encrypting message';
$labels['signing_failed'] = 'Signing message failed';
$labels['signing_message'] = 'Signing message';

// passphrase
$labels['passphrase'] = 'Passphrase';
$labels['missing_passphrase'] = 'Missing passphrase';
$labels['remember_this_session'] = 'Ricorda per questa sessione';
$labels['select_key'] = 'Seleziona chiave';

// show and preview
$labels['key_mismatch'] = 'Questo messaggio non è stato creato per questa chiave privata';
$labels['message_decrypted'] = 'Message decrypted';
$labels['decrypting_message'] = 'Decrypting message';
$labels['no_key_imported'] = 'Rilevato contenuto PGP cifrato ma non è stata importata alcuna chiave privata. Importa la tua chiave privata usanda il Gestore chiavi!';
$labels['signature_invalid_sender'] = 'Impossibile verificare la firma: indirizzo mail del mittente sconosciuto';
$labels['signature_invalid_no_pubkey'] = 'Impossibile verificare la firma: nessuna chiave pubblica trovata per ';
$labels['signature_invalid'] = 'ATTENZIONE: Firma non valida';
$labels['signature_valid'] = 'Firma valida';
