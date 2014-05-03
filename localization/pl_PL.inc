<?php
$labels = array();
// general
$labels['no_window_crypto'] = 'UWAGA! Twoja przeglądarka nie obsługuje bibliotek window.crypto (wymaganych do prawidłowego działania szyforwania OpenPGP.js)';

// key manager
$labels['action'] = 'Akcja';
$labels['algorithm'] = 'Algorithm';
$labels['bits'] = 'Bitów';
$labels['delete'] = 'Usuń';
$labels['delete_priv'] = 'Czy usunąć ten klucz prywatny?';
$labels['delete_pub'] = 'Czy usunąć ten klucz publiczny?';
$labels['fingerprint'] = 'Odcisk';
$labels['generate'] = 'Generuj';
$labels['generate_keys'] = 'Generuj klucze';
$labels['ident'] = 'Tożsamość';
$labels['import_completed'] = 'Import completed';
$labels['import_failed'] = 'Nie można zaimportować klucza, prawdopodobnie zły format pliku';
$labels['import_fail'] = 'Import nieudany';
$labels['import_gen'] = 'Sukces! Proszę zapisać swój klucz prywatny w bezpiecznym miejscu, najlepiej szyforwanym pliku. Twój klucz prywatny nie jest transferowany na serwer.';
$labels['import'] = 'Import';
$labels['import_private'] = 'Import klucza prywatnego';
$labels['import_public'] = 'Import klucza publicznego';
$labels['invalid'] = 'Nieprawidłowe';
$labels['key_generation_failed'] = 'Key generation failed';
$labels['key_generation_completed'] = 'Key generation completed';
$labels['key_id'] = 'ID Klucza';
$labels['key_manager'] = 'Zarządzanie kluczami';
$labels['key_search'] = 'Szukaj klucza';
$labels['length_alg'] = 'Długość/Algorytm';
$labels['pass_mismatch'] = 'Hasło powtórzone z błędem';
$labels['person'] = 'Osoba';
$labels['private_keys'] = 'Klucze prywatne';
$labels['pubkey_import_success'] = 'Klucz publiczny zaimportowany pomyślnie';
$labels['public_keys'] = 'Klucze publiczne';
$labels['search_description'] = 'Użyj tego pola szukania by znaleźć i zaimportować klucze publiczne do bazy lokalnej.';
$labels['search_no_keys'] = 'Żaden klucz nie pasuje do wyszukiwania, spróbuj innej frazy.';
$labels['status'] = 'Status';
$labels['valid'] = 'Prawidłowy';
$labels['verify'] = 'Powtórz hasło';

// key select
$labels['incorrect_pass'] = 'Błędne hasło';
$labels['none'] = 'brak';
$labels['selected'] = 'Wybrany';
$labels['key_select'] = 'Select key';

// settings
$labels['always_encrypt'] = 'Zawsze szyfruj wiadomości';
$labels['always_sign'] = 'Zawsze podpisuj cyfrowo wiadomości';
$labels['openpgp_options'] = 'Ustawienia i działanie zarządzania kluczami';

// compose
$labels['continue_unencrypted'] = 'Czy kontynuować wysyłanie niepodpisanej i niezaszyfrowanej wiadomości?';
$labels['encrypt'] = 'Zaszyfruj';
$labels['enter_pass'] = 'Proszę podać hasło';
$labels['no_keys'] = 'Proszę wygenerować lub zaimportować klucze w Zarządzaniu kluczami!';
$labels['save_draft_confirm'] = 'Szyfrowanie jest włączone, czy na pewno zapisywać szkic wiadomości? Zgadzając się zapisana zostanie niezaszyfrowana wiadomość na serwerze.';
$labels['sign'] = 'Podpisz (szyfrowanie i podpis cyfrowy działają tylko z wiadomościami bez HTML, zwykły tekst)';

// passphrase
$labels['passphrase'] = 'Hasło';
$labels['remember_this_session'] = 'Zapamiętaj dla tej sesji';
$labels['select_key'] = 'Wybierz i potwierdź klucz';

// show and preview
$labels['key_mismatch'] = 'Ta wiadomość nie była przeznaczona dla tego klucza prywatnego';
$labels['no_key_imported'] = 'Wykryto zaszyfrowaną metodą PHP zawartość ale nie ma zaimportowanych kluczy prywatnych. Proszę zaimportować swój klucz prywatny za pomoca Zarządzania kluczami!';
$labels['signature_invalid_sender'] = 'Nie mogę sprawdzić podpisu cyfrowego: Nie rozpoznano prawidłowego adresu email';
$labels['signature_invalid_no_pubkey'] = 'Nie mogłem zweryfikować podpisu cyfrowego: Nie znaleziono publicznego klucza dla ';
$labels['signature_invalid'] = 'UWAGA: Błędny podpis cyfrowy';
$labels['signature_valid'] = 'Podpis cyfrowy prawidłowy';
