/**
 * Roundcube plugin adding OpenPGP support using OpenPGP.js
 *
 * @version @package_version@
 * @author Lazlo Westerhof <hello@lazlo.me>
 * @author Niklas Femerstrand <nik@qnrq.se>
 *
 * @licstart  The following is the entire license notice for the
 * JavaScript code in this file.
 *
 * Copyright (C) 2013 Niklas Femerstrand <nik@qnrq.se>
 * Copyright (C) 2013-2014, Lazlo Westerhof <hello@lazlo.me>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * @licend  The above is the entire license notice
 * for the JavaScript code in this file.
 */

// load OpenPGP.js and keyring
var openpgp = typeof window !== 'undefined' && window.openpgp ? window.openpgp : require('openpgp'),
  keyring = new openpgp.Keyring(),
  settings;

// initiate OpenPGP.js web worker
openpgp.initWorker('plugins/roundcube_openpgp/lib/openpgp.worker.min.js');

window.rcmail && rcmail.addEventListener('init', function(evt) {
  // check if window.crypto.getRandomValues is present
  if (!window.crypto || !window.crypto.getRandomValues) {
    rcmail.display_message(rcmail.gettext("no_window_crypto", "roundcube_openpgp"), "error");
  }

  rcmail.passphrase = "";
  rcmail.addEventListener("plugin.pks_search", rcmail.openpgp_pks_search_callback);

  if (sessionStorage.length > 0) {
    rcmail.passphrase = sessionStorage[0];
  }

  // key selector
  $("#openpgpjs_key_select").dialog({
    modal: true,
    autoOpen: false,
    title: rcmail.gettext("key_select", "roundcube_openpgp"),
    width: "800px",
    open: function () {
      rcmail.openpgp_update_key_selector();
    },
    close: function () {
      $("#selected_key_passphrase").val("");
      $("#openpgpjs_rememberpass").attr("checked", false);
    }
  });

  // key manager
  $("#openpgpjs_key_manager").dialog({
    modal: true,
    autoOpen: false,
    title: rcmail.gettext("key_manager", "roundcube_openpgp"),
    width: "1200px",
    open: function () {
      rcmail.openpgp_update_key_manager();
    },
    close: function () {
      // empty message containers
      $(".manager-objects").html("");
    }
  });
  $("#openpgpjs_tabs").tabs();

  // register open key manager command
  rcmail.register_command("open-key-manager", function () {
    $("#openpgpjs_key_manager").dialog("open");
  });
  rcmail.enable_command("open-key-manager", true);

  // composing messages
  if (rcmail.env.action === "compose") {
    // load openpgp settings
    settings = rcmail.env.openpgp_settings;

    rcmail.addEventListener("change_identity", function () {
      sessionStorage.clear();
      rcmail.passphrase = "";
    });

    // disable draft autosave and prompt user when saving plaintext message as draft
    rcmail.env.draft_autosave = 0;
    rcmail.addEventListener("beforesavedraft", function () {
      if ($("#openpgpjs_encrypt").is(":checked")) {
        if (!confirm(rcmail.gettext("save_draft_confirm", "roundcube_openpgp"))) {
          return false;
        }
      }
      return true;
    });

    rcmail.env.compose_commands.push("open-key-manager");
    rcmail.addEventListener("beforesend", function (e) {
      if (!rcmail.openpgp_before_send()) {
        return false;
      }
    });
  // process received message
  } else if (rcmail.env.action === "show" || rcmail.env.action === "preview") {
    rcmail.openpgp_message_received();
  }
});


/**
 * Processes received messages
 */
rcube_webmail.prototype.openpgp_message_received = function()
{
  // get armored message
  var msg_armor = $("#messagebody div.message-part pre").html();

  // OpenPGP failed parsing the message, no action required.
  if (!msg_armor) {
    return;
  }

  // try to read message as cleartext
  var message,
    cleartext = false;
  try {
    message = openpgp.cleartext.readArmored(msg_armor);
    cleartext = true;
  } catch (e) {
    // message is not cleartext
    try {
      message = openpgp.message.readArmored(msg_armor);
      cleartext = false;
    } catch (e) {
      // messsage is invalid
      return false;
    }
  }

  // display key info
  this.openpgp_display_key_info(message);

  var sender = this.openpgp_get_sender();
  var publicKey = keyring.publicKeys.getForAddress(sender);

  // check if sender public key is found
  if (publicKey.length !== 1) {
    this.openpgp_display_message(
      rcmail.gettext('signature_invalid_no_pubkey', 'roundcube_openpgp') + sender,
      'notice',
      'message-objects'
    );
    return false;
  }

  // message is cleartext signed
  if (cleartext) {
    // verify signature of clear signed message
    openpgp.verifyClearSignedMessage(publicKey, message, function(err, data) {
      // valid signature
      if (data) {
        if (data.signatures.length > 0) {
        rcmail.openpgp_display_message(
          rcmail.gettext('signature_valid', 'roundcube_openpgp') + ' (' + sender + ')',
          'confirmation',
          'message-objects'
        );
        $("#messagebody div.message-part pre").html(rcmail.openpgp_escape_html(message.text));
        return true;
        }
      }
      // invalid signature
      rcmail.openpgp_display_message(
        rcmail.gettext('signature_invalid', 'roundcube_openpgp'),
        'error',
        'message-objects'
      );
      return false;
    });
  } else {
    // check if there are private key imported in the key manager
    if (!this.openpgp_private_key_count()) {
      this.display_message(
        this.gettext("no_key_imported", "roundcube_openpgp"),
        "error"
      );
      return false;
    }

    // if no passphrase was entered apen key selection dialog
    if (this.passphrase === "") {
      $("#openpgpjs_key_select").dialog("open");
      return false;
    }

    // json string from this.openpgp_set_passphrase, obj.id = privkey id, obj.passphrase = privkey passphrase
    var passobj = JSON.parse(this.passphrase);
    var privateKeyArmored = keyring.privateKeys.keys[passobj.id].armor();
    var privateKey = openpgp.key.readArmored(privateKeyArmored);

    if (!privateKey.keys[0].decrypt(passobj.passphrase)) {
      alert(this.gettext("incorrect_pass", "roundcube_openpgp"));
      return false;
    }

    // decrypt message
    var decrypting = this.display_message(
      this.gettext('decrypting_message', 'roundcube_openpgp'),
      'loading'
    );
    openpgp.decryptAndVerifyMessage(privateKey.keys[0], publicKey, message, function(err, data) {
      if (data) {
        if (data.signatures.length > 0) {
          rcmail.openpgp_display_message(
            rcmail.gettext('signature_valid', 'roundcube_openpgp') + ' (' + sender + ')' ,
            'confirmation',
            'message-objects'
          );
        }
        $("#messagebody div.message-part pre").html(rcmail.openpgp_escape_html(data.text));
        rcmail.hide_message(decrypting);
        rcmail.display_message(
          rcmail.gettext('message_decrypted', 'roundcube_openpgp'),
          'confirmation',
          rcmail.message_time
        );
        return true;
      }
      rcmail.openpgp_display_message(
        rcmail.gettext('key_mismatch', 'roundcube_openpgp'),
        'error',
        'message-objects'
      );
      return false;
    });
  }
};


/**
 * Returns the sender of message.
 *
 * @return {String} Message sender
 */
rcube_webmail.prototype.openpgp_get_sender = function()
{
  // this.env.sender contains "Jon Doe <jd@example.com>" or just "jd@example.com";
  // We try to extract the email address (according to RFC 5322) in either case
  var address = this.env.sender.match(/[A-Za-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9._-]+\.[a-zA-Z0-9._-]+/);

  if (!address || !address.length) {
    // In the case of a bogus sender name/address, throw an error
    this.openpgp_display_message(
      this.gettext('signature_invalid_sender', 'roundcube_openpgp'),
      'notice',
      'message-objects'
    );
    return false;
  }
  return address[0];
};


/**
 * Extracts public key info from parsed OpenPGP message.
 *
 * @param message {String} Parsed OpenPGP message
 */
rcube_webmail.prototype.openpgp_display_key_info = function(message)
{
  // get fingerprint from sender's public key
  try {
    var sender = this.env.sender.match(/[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g)[0],
      publicKey = keyring.publicKeys.getForAddress(sender),
      fingerprint = publicKey[0].primaryKey.getFingerprint().toUpperCase().replace(/(.{4})/g,"$1 ");
  } catch (e) {
    return false;
  }

  if (typeof(this.getinfo) === "undefined") {
    var creation = message.packets[0].created;
    $(".headers-table").css( "float", "left" ).after("<table class='openpgpjs_info headers-table'><tbody></tbody></table>");

    $(".openpgpjs_info tbody").append(
      "<tr><td class='header-title'>"+this.gettext("algorithm", "roundcube_openpgp") +":</td>" +
      "<td class='header'>" + this.openpgp_type_to_string(message.packets[0].publicKeyAlgorithm) + "</td></tr>" +
      "<tr><td class='header-title'>"+this.gettext("creation", "roundcube_openpgp") +":</td>" +
      "<td class='header'>" + creation.getFullYear() + "-" +  ("0" + (creation.getMonth()+1)).slice(-2) + "-" + ("0" + creation.getDate()).slice(-2) + "</td></tr>" +
      "<tr><td class='header-title'>"+this.gettext("fingerprint", "roundcube_openpgp") +":</td>" +
      "<td class='header'>" + fingerprint + "</td></tr>"
    );
    this.getinfo = false;
  }
};


/**
 * Generates an OpenPGP key pair by calling the necessary crypto
 * functions from openpgp.js and shows them to the user.
 *
 * @param bits {Integer} Number of bits for the key creation
 * @param algo {String} To indicate what type of key to make. RSA is 1, ElgAmal is 16 and DSA is 17
 */
rcube_webmail.prototype.openpgp_generate_key_pair = function(bits, algorithm)
{
  $("#generated_keys").html("");
  var identity = $("#gen_ident option:selected").text();

  // currently only RSA is supported, fix this when OpenPGP.js implements ElGamal & DSA
  algorithm = parseInt(algorithm);

  if ($("#gen_passphrase").val() !== $("#gen_passphrase_verify").val()) {
    this.openpgp_display_message(
      this.gettext("pass_mismatch", "roundcube_openpgp"),
      'error',
      'generate_key_msg'
    );
    return false;
  }

  // generate key pair and show generated key pair
  openpgp.generateKeyPair(algorithm, bits, identity, $("#gen_passphrase").val(), function(err, data) {
    if (data) {
      $("#generated_keys").html(
        "<pre id=\"generated_private\">" + data.privateKeyArmored + "</pre>" +
        "<pre id=\"generated_public\">" + data.publicKeyArmored  +  "</pre>"
      );
      rcmail.openpgp_display_message(
        rcmail.gettext("key_generation_completed", "roundcube_openpgp"),
        'confirmation',
        'generate_key_msg'
      );
      $("#import_button").removeClass("hidden");
    } else {
      rcmail.openpgp_display_message(
        rcmail.gettext("key_generation_failed", "roundcube_openpgp"),
        'error',
        'generate_key_msg'
      );
    }
  });
};


/**
 * Set passphrase.
 *
 * @param i {Integer} Used as openpgp.keyring[private|public]Keys[i]
 * @param p {String}  The passphrase
 */
rcube_webmail.prototype.openpgp_set_passphrase = function(id, passphrase)
{
  if (id === "-1") {
    this.openpgp_display_message(
      this.gettext("select_key", "roundcube_openpgp"),
      'error',
      'key_select_msg'
    );
    return false;
  }

  if (!keyring.privateKeys.keys[id].decrypt(passphrase)) {
    this.openpgp_display_message(
      this.gettext("incorrect_pass", "roundcube_openpgp"),
      'error',
      'key_select_msg'
    );
    return false;
  }

  this.passphrase = JSON.stringify({"id" : id, "passphrase" : passphrase} );
  this.openpgp_message_received();

  if ($("#openpgpjs_rememberpass").is(":checked")) {
    sessionStorage.setItem(id, this.passphrase);
  }

  $("#openpgpjs_key_select").dialog("close");

  // This is required when sending emails and private keys are required for
  // sending an email (when signing a message). These lines makes the client
  // jump right back into this.openpgp_before_send() allowing key sign and message send to
  // be made as soon as the passphrase is correct and available.
  if (this.sendmail !== "undefined") {
    this.command("send", this);
  }
};


rcube_webmail.prototype.openpgp_recipient_public_keys = function()
{
  var publicKeys = [],
    recipients = [],
    matches = [],
    fields = ["_to", "_cc", "_bcc"],
    re = /[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g;

  // retrieve all recipients
  for (var field in fields) {
    matches = $("#" + fields[field]).val().match(re);
    if (matches) {
      recipients = recipients.concat(matches);
    }
  }

  for (var i = 0; i < recipients.length; i++) {
    var recipient = recipients[i].replace(/(.+?<)/, "").replace(/>/, "");
    var publicKey = keyring.publicKeys.getForAddress(recipient);
    if (typeof(publicKey[0]) !== "undefined") {
      publicKeys.push(publicKey[0]);
    } else {
      // query PKS for recipient public key
      if (confirm("Couldn't find a public key for " + recipient +
                  ". If you already have it you can import it into the key manager. " +
                  "Would you like to query the key server for the missing key?")) {
        this.http_post("plugin.pks_search", "search=" + recipient + "&op=index");
        $("#search").attr("disabled", "disabled");
        $("#search_submit").attr("disabled", "disabled");
        $("#openpgpjs_key_manager").dialog("open");
        // open key search tab
        $("#openpgpjs_tabs").tabs({ active: 5 });
      }
      return false;
    }
  }

  return publicKeys;
};


/**
 * Get the user's public key
 */
rcube_webmail.prototype.openpgp_senders_public_key = function(armored)
{
  if (typeof(armored) === "undefined") {
    armored = false;
  }

  var re = /[a-zA-Z0-9\._%+-]+@[a-zA-Z0-9\._%+-]+\.[a-zA-Z]{2,4}/g;
  var address = $("#_from>option:selected").html().match(re);
  if (address.length > 0) {
    var publicKey = keyring.publicKeys.getForAddress(address[0]);
    if (typeof(publicKey[0]) != "undefined") {
      if (armored) {
        return publicKey[0].armor();
      } else {
        return publicKey[0];
      }
    }
  }
  return false;
};


/**
 * Processes messages before sending
 */
rcube_webmail.prototype.openpgp_before_send = function()
{
  // no encryption and / or signing
  if (!$("#openpgpjs_encrypt").is(":checked") &&
      !$("#openpgpjs_sign").is(":checked")) {
    if (settings.warn_on_unencrypted) {
      if (confirm(this.gettext("continue_unencrypted", "roundcube_openpgp"))) {
        // remove the public key attachment since we don't sign nor encrypt the message
        this.openpgp_remove_public_key_attachment();
        return true;
      }
      return false;
    }
    return true;
  }

  // message is already processed
  if (typeof(this.finished_treating) !== "undefined") {
    return true;
  }

  // send the user's public key to the server so it can be sent as attachment
  var pubkey_sender = this.openpgp_senders_public_key(true);
  if (pubkey_sender) {
    var lock = this.set_busy(true, 'loading');
    this.http_post('plugin.write_public_key', { _publickey: pubkey_sender }, lock);
  }

  // message to encrypt and / or sign
  var plaintext = $("textarea#composebody").val(),
    privateKey;

  // message is going to be signed
  if ($("#openpgpjs_sign").is(":checked")) {
    // get the private key
    if (this.passphrase === "" && this.openpgp_private_key_count() > 0) {
      this.sendmail = true; // Global var to notify this.openpgp_set_passphrase
      $("#openpgpjs_key_select").dialog("open");
      return false;
    }

    if (!this.openpgp_private_key_count()) {
      alert(this.gettext("no_keys", "roundcube_openpgp"));
      return false;
    }

    // get private key for signing
    var passobj = JSON.parse(this.passphrase),
      privateKeyArmored = keyring.privateKeys.keys[passobj.id].armor();
      privateKey = openpgp.key.readArmored(privateKeyArmored);

    if (!privateKey) {
      alert("Missing private key");
      return false;
    }

    if (!passobj.passphrase) {
      this.display_message(
        this.gettext("missing_passphrase", "roundcube_openpgp"),
        'error'
      );
      return false;
    }

    if (!privateKey.keys[0].decrypt(passobj.passphrase)) {
      alert(this.gettext("incorrect_pass", "roundcube_openpgp"));
    }
  }

  // message is going to be encrypted
  if ($("#openpgpjs_encrypt").is(":checked")) {
    // fetch recipient public keys
    var publicKeys = this.openpgp_recipient_public_keys();
    if (publicKeys.length === 0) {
      return false;
    }

    // add the user's public key
    var senderPublicKeySender = this.openpgp_senders_public_key();
    if (senderPublicKeySender) {
      publicKeys.push(senderPublicKeySender);
    } else {
      if (!confirm("Couldn't find your public key. You will not be able to decrypt this message. Continue?")) {
        return false;
      }
    }

    // sign and encrypt message
    if ($("#openpgpjs_sign").is(":checked")) {
      var encryptingAndSigning = this.display_message(
        this.gettext('signing_and_encrypting_message', 'roundcube_openpgp'),
        'loading'
      );
      openpgp.signAndEncryptMessage(publicKeys, privateKey.keys[0], plaintext, function(err, data) {
        rcmail.hide_message(encryptingAndSigning);
        if (data) {
          rcmail.openpgp_replace_plaintext(data);
          rcmail.display_message(
            rcmail.gettext('message_signed_and_encrypted', 'roundcube_openpgp'),
            'confirmation',
            rcmail.message_time
          );
          return true;
        }
        rcmail.display_message(
          rcmail.gettext('signing_and_encrypting_failed', 'roundcube_openpgp'),
          'error'
        );
        return false;
      });
    }
    // encrypt message
    else {
      var encrypting = this.display_message(
        this.gettext('encrypting_message', 'roundcube_openpgp'),
        'loading'
      );
      openpgp.encryptMessage(publicKeys, plaintext, function(err, data) {
        rcmail.hide_message(encrypting);
        if (data) {
          rcmail.openpgp_replace_plaintext(data);
          rcmail.display_message(
            rcmail.gettext('message_encrypted', 'roundcube_openpgp'),
            'confirmation',
            rcmail.message_time
          );
          return true;
        }
        rcmail.display_message(
          rcmail.gettext('encrypting_failed', 'roundcube_openpgp'),
          'error'
        );
        return false;
      });
    }
  }
  // sign message
  else if ($("#openpgpjs_sign").is(":checked")) {
    var signing = this.display_message(
      this.gettext('signing_message', 'roundcube_openpgp'),
      'loading'
    );
    openpgp.signClearMessage(privateKey.keys, plaintext, function(err, data) {
      rcmail.hide_message(signing);
      if (data) {
        rcmail.openpgp_replace_plaintext(data);
        rcmail.display_message(
          rcmail.gettext('message_signed', 'roundcube_openpgp'),
          'confirmation',
          rcmail.message_time
        );
        return true;
      }
      rcmail.display_message(
        rcmail.gettext('signing_failed', 'roundcube_openpgp'),
        'error'
      );
      return false;
    });
  }

  return false;
};


/**
 * Replaces plaintext with signed and / or encrypted text
 *
 * @param text {String} signed and / or encrypted text
 */
rcube_webmail.prototype.openpgp_replace_plaintext = function(text)
{
  $("textarea#composebody").val(text);
  this.finished_treating = 1;
};


/**
 * Removes the public key attachment
 * Used if the user doesn't sign nor encrypt the message
 */
rcube_webmail.prototype.openpgp_remove_public_key_attachment = function()
{
  $("#attachment-list").each(function () {
    $(this).find('li').each(function () {
      if ($(this).text().indexOf('pubkey.asc') >= 0) {
        this.command('remove-attachment', $(this).attr('id'));
        return false;
      }
    });
  });
};


rcube_webmail.prototype.openpgp_import_from_sks = function(id)
{
  this.http_post("plugin.pks_search", "search=" + id + "&op=get");
  return;
};


/**
 * Import generated key pair.
 */
rcube_webmail.prototype.openpgp_import_generated_key_pair = function()
{
  $("#import_button").addClass("hidden");

  // import keys and change tabs
  this.openpgp_import_keys($("#generated_public").html() + $("#generated_private").html());
  $("#openpgpjs_tabs").tabs({ active: 3 });

  $("#gen_passphrase").val("");
  $("#gen_passphrase_verify").val("");
};


/**
 * Import armored public and private keys
 *
 * @param armored {String} Armored public and private keys
 */
rcube_webmail.prototype.openpgp_import_keys = function(armored)
{
  // empty message container
  $('#import_keys_msg').html('');

  // match all public and private keys in armored input
  var publicKeys = armored.match(/-----BEGIN PGP PUBLIC KEY BLOCK-----[\s\S]+?-----END PGP PUBLIC KEY BLOCK-----/g),
    privateKeys = armored.match(/-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----/g),
    key;


  if (!publicKeys && !privateKeys) {
    this.openpgp_display_message(
      this.gettext("import_failed", "roundcube_openpgp"),
      'error',
      'import_keys_msg',
      false
    );
  }

  if (publicKeys) {
    publicKeys.forEach(function(publicKey) {
      try {
        key = openpgp.key.readArmored(publicKey);
        // store public key in keyring
        keyring.publicKeys.importKey(publicKey);
        keyring.store();

        rcmail.openpgp_display_message(
          rcmail.gettext("import_public", "roundcube_openpgp") + " " + key.keys[0].getUserIds()[0],
          'confirmation',
          'import_keys_msg',
          false
        );
      } catch (e) {
        rcmail.openpgp_display_message(
          rcmail.gettext("import_failed", "roundcube_openpgp"),
          'error',
          'import_keys_msg',
          false
        );
      }
    });
  }

  if (privateKeys) {
    privateKeys.forEach(function(privateKey) {
      try {
        key = openpgp.key.readArmored(privateKey);

        // store private key in keyring
        keyring.privateKeys.importKey(privateKey);
        keyring.store();

        rcmail.openpgp_display_message(
          rcmail.gettext("import_private", "roundcube_openpgp") + " " + key.keys[0].getUserIds()[0],
          'confirmation',
          'import_keys_msg',
          false
        );
      } catch (e) {
        rcmail.openpgp_display_message(
          rcmail.gettext("import_failed", "roundcube_openpgp"),
          'error',
          'import_keys_msg',
          false
        );
      }
    });
  }

  // update key manager and empty import form
  this.openpgp_update_key_manager();
  $("#keys").val("");
};


/**
 * Export public and private keys as armored text
 */
rcube_webmail.prototype.openpgp_export_keys = function()
{
  var i, j, exported = '';

  try {
    // empty message container
    $('#export_keys_msg').html('');

    // empty export textarea
    $('#export').html('');

    // loop through all public keys
    for (i = 0; i < keyring.publicKeys.keys.length; i++) {
      exported = exported + keyring.publicKeys.keys[i].armor();
    }

    // loop through all private keys
    for (i = 0; i < this.openpgp_private_key_count(); i++) {
      exported = exported + keyring.privateKeys.keys[i].armor();
    }

    $('#export').html(exported);

    rcmail.openpgp_display_message(
      rcmail.gettext("export_complete", "roundcube_openpgp"),
      'confirmation',
      'export_keys_msg'
    );
  } catch (e) {
    rcmail.openpgp_display_message(
      rcmail.gettext("export_failed", "roundcube_openpgp"),
      'error',
      'export_keys_msg'
    );
  }


};


/**
 * op: (get|index|vindex) string operation to perform
 * search: string phrase to pass to HKP
 *
 * To retrieve all matching keys: this.openpgp_public_key_search("foo@bar", "index")
 * To retrieve armored key of specific id: this.openpgp_public_key_search("0xF00", "get")
 *
 * If op is get then search should be either 32-bit or 64-bit. See
 * http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00#section-3.1.1.1
 * for more details.
 *
 */
// TODO: Version 3 fingerprint search
rcube_webmail.prototype.openpgp_public_key_search = function(search, op)
{
  if (search.length === 0) {
    return false;
  }

  this.http_post("plugin.pks_search", "search=" + search + "&op=" + op);
  return true;
};

rcube_webmail.prototype.openpgp_pks_search_callback = function(response)
{
  $("#search").removeAttr("disabled");
  $("#search_submit").removeAttr("disabled");

  if (response.message === "ERR: Missing param") {
    console.log("Missing param");
    return false;
  }

  if (response.message === "ERR: Invalid operation") {
    console.log("Invalid operation");
    return false;
  }

  if (response.message === "ERR: No keys found") {
      $("#openpgpjs_search_results tbody").html(rcmail.gettext("search_no_keys", "roundcube_openpgp"));
      return false;
  }

  var result;
  if (response.op === "index") {
    // clear results table
    $("#openpgpjs_search_results tbody").html("");
    try {
      result = JSON.parse(response.message);
    } catch (e) {
      $("#openpgpjs_search_results tbody").html(rcmail.gettext("search_no_keys", "roundcube_openpgp"));
      return false;
    }

    // print search results to table
    for (var i = 0; i < result.length; i++) {
      $("#openpgpjs_search_results tbody").append(
        "<tr><td>" + result[i][0] + "</td>" +
        "<td>" + result[i][1] + "</td>" +
        "<td><a href='#' onclick='rcmail.openpgp_import_from_sks(\"" + result[i][0] + "\");'>Import</a></td></tr>"
      );
    }
  } else if (response.op === "get") {
    var k = JSON.parse(response.message);

    // import key and change tab
    rcmail.openpgp_import_keys(String(k[0]));
    $("#openpgpjs_tabs").tabs({ active: 3 });
  }
};


/**
 * Returns the number of private keys in keyring
 *
 * @return {Integer}
 */
rcube_webmail.prototype.openpgp_private_key_count = function()
{
  return keyring.privateKeys.keys.length;
};


/**
 * Select a private key.
 *
 * @param i {Integer} Used as openpgp.keyring[private|public]Keys[i]
 */
rcube_webmail.prototype.openpgp_select_key = function(id)
{
  $("#openpgpjs_selected i").html(
    $("#key_" + id).html()
  );
  $("#openpgpjs_selected_id").val(id);
  $("#passphrase").val("");
};


/**
 * Update key selector dialog.
 */
rcube_webmail.prototype.openpgp_update_key_selector = function()
{
  var privateKeys = this.openpgp_private_key_count();

  // empty key selection list
  $("#openpgpjs_key_select_list tbody").html("");
  // selected set as $("#openpgpjs_selected_id").val(), then get that value from this.openpgp_set_passphrase
  for (var i = 0; i < privateKeys; i++) {
    var userIds = keyring.privateKeys.keys[i].getUserIds()
    for (var j = 0; j < userIds.length; j++) {
      $("#openpgpjs_key_select_list tbody").append(
        "<tr class=\"clickme\" id=\"key_" + i +"\"onclick=\"rcmail.openpgp_select_key(" + i + ");\">" +
        "<td>" + this.openpgp_get_fingerprint(i, true) + "</td>" +
        "<td>" + this.openpgp_escape_html(userIds[j]) + "</td>" +
        "</tr>"
      );
    }
  }

  // only one key in keyring, nothing to select from
  if (privateKeys === 1) {
    $("#openpgpjs_key_select_list").addClass('hidden');
    $("#openpgpjs_selected_id").val(0);
    this.openpgp_select_key(0);
  }

  return true;
};


/**
 * Converts an algorithm type to the algorithm string for output
 *
 * @param type {String} Algorithm type
 * @return {String} Algorithm string
 */
rcube_webmail.prototype.openpgp_type_to_string = function(type)
{
  if(isNaN(type)) {
    type = openpgp.enums.publicKey[type];
  }

  switch(type) {
    // rsa_encrypt_sign
    case 1:
      return "RSA (encrypt/sign)";
    // rsa_encrypt
    case 2:
      return "RSA (encrypt)";
    // rsa_sign
    case 3:
      return "RSA (sign)";
    // elgamal
    case 16:
      return "Elgamal";
    // dsa
    case 17:
      return "DSA";
    // unknown
    default:
      return "Unknown";
  }
};


/**
 * Extracts the algorithm string from a key and return the algorithm type.
 *
 * @param id {Integer} Key id in keyring
 * @return {String} Algorithm type
 */
rcube_webmail.prototype.openpgp_get_algorithm = function(id, private=false)
{
  var key;
  if (private) {
    key = keyring.privateKeys.keys[id].primaryKey;
  } else {
    key = keyring.publicKeys.keys[id].primaryKey;
  }
  return key.mpi[0].byteLength() * 8 + "/" + this.openpgp_type_to_string(key.algorithm);
};


/**
 * Returns the status of the key as String (invalid, expired, revoked,
 * valid, no self cert)
 *
 * @param id {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @return {String} Key status
 */
rcube_webmail.prototype.openpgp_verify_key = function(id, private=false)
{
  var status;
  if (private) {
    status = keyring.privateKeys.keys[id].verifyPrimaryKey();
  } else {
    status = keyring.publicKeys.keys[id].verifyPrimaryKey();
  }

  switch(status) {
    // invalid
    case 0:
      return this.gettext("invalid", "roundcube_openpgp");
    // expired
    case 1:
      return this.gettext("expired", "roundcube_openpgp");
    // revoked
    case 2:
      return this.gettext("revoked", "roundcube_openpgp");
    // valid
    case 3:
      return this.gettext("valid", "roundcube_openpgp");
    // no self cert
    case 4:
      return this.gettext("invalid", "roundcube_openpgp");
    // invalid
    default:
      return this.gettext("invalid", "roundcube_openpgp");
  }
};


/**
 * Returns the fingerprint of a key in the keyring
 *
 * @param id {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @param niceformat {Boolean} Use nice formatting
 * @return {Integer}
 */
rcube_webmail.prototype.openpgp_get_fingerprint = function(id, private=false, niceformat=true)
{
  var fingerprint;
  if (private) {
    fingerprint = keyring.privateKeys.keys[id].primaryKey.getFingerprint().toUpperCase();
  } else {
    fingerprint = keyring.publicKeys.keys[id].primaryKey.getFingerprint().toUpperCase();
  }

  fingerprint = fingerprint.replace(/(.{4})/g, "$1 ");

  return fingerprint;
};


/**
 * Tries to temove key from keyring and returns if it is removed.
 *
 * @param id {Integer} Key id in keyring
 * @param private {Boolean} Private key
 * @return {Boolean}
 */
rcube_webmail.prototype.openpgp_remove_key = function(id, private)
{
  if (private) {
    keyring.privateKeys.removeForId(id);
  } else {
    keyring.publicKeys.removeForId(id);
  }
  keyring.store();
};


/**
 * Escape some unsafe characters into their html entities.
 *
 * @param unsafe {String} Unsafe string to escape
 */
rcube_webmail.prototype.openpgp_escape_html = function(unsafe)
{
  return unsafe.replace(/&/g, "&amp;")
               .replace(/</g, "&lt;")
               .replace(/>/g, "&gt;")
               .replace(/"/g, "&quot;")
               .replace(/'/g, "&#039;");
};


/**
 * Display a custom message above the email body, analogous to
 * Roundcubes privacy warning message.
 *
 * @param msg  {String} Message to display
 * @param type {String} One of 'confirmation', 'notice', 'error'
 * @param id {String} Id of message container
 */
rcube_webmail.prototype.openpgp_display_message = function(msg, type, id, empty=true)
{
  // empty message container
  if(empty) {
    $('#' + id).html('');
  }

  // insert a message into message container
  $('<div>').text(msg).addClass(type).addClass('messagepadding').appendTo($('#' + id));
};


/**
 * Updates key manager public keys table, private keys table
 * and identy selector.
 */
rcube_webmail.prototype.openpgp_update_key_manager = function()
{
  // empty public key table
  $("#openpgpjs_pubkeys tbody").empty();

  var i, keyId, fingerprint, person, length_alg, created, expired, status, del, exp, result;

  // fill public key table
  for (i = 0; i < keyring.publicKeys.keys.length; i++) {
    keyId = keyring.publicKeys.keys[i].primaryKey.getKeyId().toHex();
    fingerprint = this.openpgp_get_fingerprint(i);
    person = this.openpgp_escape_html(keyring.publicKeys.keys[i].getUserIds()[0]);
    length_alg = this.openpgp_get_algorithm(i);
    creation = keyring.publicKeys.keys[i].primaryKey.created;
    expiration = this.gettext("no_expiration", "roundcube_openpgp");
    if (keyring.publicKeys.keys[i].getExpirationTime()) {
      expiration = keyring.publicKeys.keys[i].getExpirationTime();
      expiration = expiration.getFullYear() + "-" +  ("0" + (expiration.getMonth()+1)).slice(-2) + "-" + ("0" + expiration.getDate()).slice(-2);
    }
    status = this.openpgp_verify_key(i);
    del = "<a href='#' onclick='if (confirm(\"" + this.gettext('delete_pub', 'roundcube_openpgp') + "\")) { rcmail.openpgp_remove_key(\"" + keyId + "\", false); rcmail.openpgp_update_key_manager(); }'>" + this.gettext('delete', 'roundcube_openpgp') + "</a>";
    exp = "<a href=\"data:asc," + encodeURIComponent(keyring.publicKeys.keys[i].armor()) + "\" download=\"pubkey_" + "0x" + keyId.toUpperCase().substring(8) + ".asc\">Export</a> ";
    result = "<tr>" +
      "<td>" + fingerprint + "</td>" +
      "<td>" + person      + "</td>" +
      "<td>" + length_alg  + "</td>" +
      "<td>" + creation.getFullYear() + "-" +  ("0" + (creation.getMonth()+1)).slice(-2) + "-" + ("0" + creation.getDate()).slice(-2) + "</td>" +
      "<td>" + expiration  + "</td>" +
      "<td>" + status      + "</td>" +
      "<td>" + exp + del   + "</td>" +
      "</tr>";

    // add key to public key table
    $("#openpgpjs_pubkeys tbody").append(result);
  }

  // empty private key table
  $("#openpgpjs_privkeys tbody").empty();

  // fill private key table
  for (i = 0; i < this.openpgp_private_key_count(); i++) {
    for (var j = 0; j < keyring.privateKeys.keys[i].getUserIds().length; j++) {
      keyId = keyring.privateKeys.keys[i].primaryKey.getKeyId().toHex();
      fingerprint = this.openpgp_get_fingerprint(i, true);
      person = this.openpgp_escape_html(keyring.privateKeys.keys[i].getUserIds()[j]);
      length_alg = this.openpgp_get_algorithm(i, true);
      creation = keyring.privateKeys.keys[i].primaryKey.created;
      expiration = this.gettext("no_expiration", "roundcube_openpgp");
      if (keyring.privateKeys.keys[i].getExpirationTime()) {
        expiration = keyring.publicKeys.keys[i].getExpirationTime();
        expiration = expiration.getFullYear() + "-" +  ("0" + (expiration.getMonth()+1)).slice(-2) + "-" + ("0" + expiration.getDate()).slice(-2);
      }
      del = "<a href='#' onclick='if (confirm(\"" + this.gettext('delete_priv', 'roundcube_openpgp') + "\")) { rcmail.openpgp_remove_key(\"" + keyId + "\", true); rcmail.openpgp_update_key_manager(); }'>" + this.gettext('delete', 'roundcube_openpgp') + "</a>";
      exp = "<a href=\"data:asc," + encodeURIComponent(keyring.privateKeys.keys[i].armor()) + "\" download=\"privkey_" + "0x" + keyId.toUpperCase().substring(8) + ".asc\">Export</a> ";
      result = "<tr>" +
        "<td>" + fingerprint + "</td>" +
        "<td>" + person      + "</td>" +
        "<td>" + length_alg  + "</td>" +
        "<td>" + creation.getFullYear() + "-" +  ("0" + (creation.getMonth()+1)).slice(-2) + "-" + ("0" + creation.getDate()).slice(-2) + "</td>" +
        "<td>" + expiration  + "</td>" +
        "<td>" + exp + del   + "</td>" +
        "</tr>";

      // add key to private key table
      $("#openpgpjs_privkeys tbody").append(result);
    }
  }

  // fill key manager generation identity selector
  $("#gen_ident").html("");
  var identities = JSON.parse($("#openpgpjs_identities").html());
  for (i = 0; i < identities.length; i++) {
    $("#gen_ident").append(
      "<option value='" + i + "'>" +
      this.openpgp_escape_html(identities[i].name + " <" + identities[i].email + ">") +
      "</option>"
    );
  }
};
