<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'WARNING! Your web browser does not support window.crypto (required by OpenPGP.js)';

// key manager
$labels['action'] = 'Action';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Taille en Bits';
$labels['delete'] = 'Supprimer';
$labels['delete_priv'] = 'Supprimer cette clef privée?';
$labels['delete_pub'] = 'Supprimer cette clef publique?';
$labels['fingerprint'] = 'Empreinte';
$labels['generate'] = 'Générer';
$labels['generate_keys'] = 'Générateur de Clef';
$labels['ident'] = 'Identité';
$labels['import_completed'] = 'Import completed';
$labels['import_failed'] = 'Impossible d\'importer la clef, éventuellement à cause d\'un mauvais format';
$labels['import_fail'] = 'Import échoué';
$labels['import_gen'] = 'Succès! S\'il vous plaît enregistrer votre clef privée dans un endroit sûr, de préférence dans un conteneur chiffré. Votre clef privée n\'est pas transférée vers le serveur.';
$labels['import'] = 'Importer';
$labels['import_private'] = 'Importer une clef privée';
$labels['import_public'] = 'Importer une clef publique';
$labels['invalid'] = 'Invalide';
$labels['key_generation_failed'] = 'Key generation failed';
$labels['key_generation_completed'] = 'Key generation completed';
$labels['key_id'] = 'ID de la clef';
$labels['key_manager'] = 'Gestionnaire de clef';
$labels['key_search'] = 'Recherche de clef';
$labels['length_alg'] = 'Longueur/Algorithme';
$labels['pass_mismatch'] = 'Phrase de chiffrement différente';
$labels['person'] = 'Personne';
$labels['private_keys'] = 'Clef privée';
$labels['pubkey_import_success'] = 'Clef publique importée avec succès';
$labels['public_keys'] = 'Clef publique';
$labels['search_description'] = 'Utilisez cette recherche pour trouver et importer des clefs publiques dans votre gestionnaire de clef local.';
$labels['search_no_keys'] = 'No keys matched your search, try another query.';
$labels['status'] = 'Statut';
$labels['valid'] = 'Valide';
$labels['verify'] = 'Vérification';

// key select
$labels['incorrect_pass'] = 'Phrase de chiffrement incorrecte';
$labels['none'] = 'aucun';
$labels['selected'] = 'Sélectionner';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Toujours chiffrer les messages';
$labels['always_sign'] = 'Toujours signer les messages';
$labels['openpgp_options'] = 'Options OpenPGP';

// compose
$labels['continue_unencrypted'] = 'Continuer à envoyer le mail en clair et non signé?';
$labels['encrypt'] = 'Chiffrer';
$labels['enter_pass'] = 'S\'il vous plaît entrer la phrase de chiffrement';
$labels['no_keys'] = 'S\'il vous plaît produire ou importer des clefs dans le gestionnaire de clef!';
$labels['save_draft_confirm'] = 'Encryption is enabled, are you sure that you want to save this draft? By doing so you save an unencrypted copy on the server.';
$labels['sign'] = 'Signer';

// passphrase
$labels['passphrase'] = 'Phrase de chiffrement';
$labels['remember_this_session'] = 'Mémoriser pour cette session.';
$labels['select_key'] = 'Veuillez selectionner une clef';

// show and preview
$labels['key_mismatch'] = 'Ce message n\'est pas prévu pour cette clef privée';
$labels['no_key_imported'] = 'Contenu PGP crypté détecté mais aucune clef privée importée. S\'il vous plaît importer votre clé PGP privée en utilisant le gestionnaire de clef!';
$labels['signature_invalid_sender'] = 'Could not verify signature: No valid sender email address recognized';
$labels['signature_invalid_no_pubkey'] = 'Could not verify signature: No public key found for ';
$labels['signature_invalid'] = 'CAUTION: Invalid signature';
$labels['signature_valid'] = 'Signature valid';
