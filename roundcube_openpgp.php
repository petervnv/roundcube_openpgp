<?php

/**
 * Roundcube plugin adding OpenPGP support using OpenPGP.js
 *
 * @version @package_version@
 * @author Lazlo Westerhof <hello@lazlo.me>
 * @author Niklas Femerstrand <nik@qnrq.se>
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
 */

class roundcube_openpgp extends rcube_plugin {
  public $task = 'mail|settings';
  public $rc;

  /**
   * Plugin initialization.
   */
  function init() {
    $this->rc = rcube::get_instance();
    $this->rm = rcmail::get_instance();

    // load configuration
    $this->load_config();

    $this->add_hook('user_create', array($this, 'user_create'));

    // register actions
    $this->register_action('plugin.pks_search', array($this, 'hkp_search'));
    $this->register_action('plugin.write_public_key', array($this, 'write_public_key'));

    // load css
    $this->include_stylesheet($this->local_skin_path() . '/roundcube_openpgp.css');

    if ($this->rc->task == 'mail') {
      $this->add_hook('render_page', array($this, 'render_page'));

      // make localization available on the client
      $this->add_texts('localization/', true);

      // load js
      $this->include_script('lib/openpgp.min.js');
      $this->include_script('roundcube_openpgp.js');

      // add public key attachment related hooks
      if ($this->rc->config->get('attach_public_key', true)) {
        $this->add_hook('message_compose', array($this, 'attach_public_key'));
        $this->add_hook('message_sent', array($this, 'delete_public_key'));
      }
      if ($this->api->output->type == 'html') {
        // add key manager item to message menu
        $opts = array("command"    => "open-key-manager",
                      "label"      => "roundcube_openpgp.key_manager",
                      "type"       => "link",
                      "classact"   => "icon active",
                      "class"      => "icon",
                      "innerclass" => "icon key_manager");
        $this->api->add_content(html::tag('li', null, $this->api->output->button($opts)), "messagemenu");

        if ($this->rc->action == 'compose') {
          // make some setting available on client
          $settings = array();
          $settings['warn_on_unencrypted'] = $this->rc->config->get('warn_on_unencrypted');
          $this->rc->output->set_env('openpgp_settings', $settings);

          // add key manager button to compose toolbar
          $opts = array("command"    => "open-key-manager",
                        "label"      => "roundcube_openpgp.key_manager",
                        "type"       => "link",
                        "classact"   => "button active key_manager",
                        "class"      => "button key_manager");
          $this->api->add_content($this->api->output->button($opts), "toolbar");

          // add encrypt and sign checkboxes to composeoptions
          $encrypt_opts = array('id' => 'openpgpjs_encrypt',
                                'type' => 'checkbox');
          if($this->rc->config->get('encrypt', false)) {
             $encrypt_opts['checked'] = 'checked';
          }
          $encrypt = new html_inputfield($encrypt_opts);
          $this->api->add_content(
            html::span('composeoption', html::label(null, $encrypt->show() . $this->gettext('encrypt'))),
            "composeoptions"
          );
          $sign_opts = array('id' => 'openpgpjs_sign',
                             'type' => 'checkbox');
          if($this->rc->config->get('sign', false)) {
             $sign_opts['checked'] = 'checked';
          }
          $sign = new html_inputfield($sign_opts);
          $this->api->add_content(
            html::span('composeoption', html::label(null, $sign->show() . $this->gettext('sign'))),
            "composeoptions"
          );
        }
      }
    } elseif ($this->rc->task == 'settings') {
      // load localization
      $this->add_texts('localization/', false);

      // add hooks for OpenPGP settings
      $this->add_hook('preferences_sections_list', array($this, 'preferences_sections_list'));
      $this->add_hook('preferences_list', array($this, 'preferences_list'));
      $this->add_hook('preferences_save', array($this, 'preferences_save'));
    }
  }

  /**
   * Add key manager and key selector to html output
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function render_page($params) {
    $template_path = $this->home . '/'. $this->local_skin_path();
    $this->rc->output->add_footer($this->rc->output->just_parse(
      file_get_contents($template_path . '/templates/key_manager.html') .
      file_get_contents($template_path . '/templates/key_search.html') .
      file_get_contents($template_path . '/templates/key_select.html')));
    $this->rc->output->add_footer(html::div(array('style' => "visibility: hidden;",
                                                  'id' => "openpgpjs_identities"),
                                  json_encode($this->rm->user->list_identities())));

    return $params;
  }

  /**
   * Create default identity, required as pubkey metadata
   */
  function user_create($params) {
    $params['user_name'] = preg_replace("/@.*$/", "", $params['user']);
    $params['user_email'] = $params['user'];
    return $params;
  }

  /**
   * This Public Key Server proxy is written to circumvent Access-Control-Allow-Origin
   * limitations. It also provides a layer of security as HKP normally doesn't
   * support HTTPS; essentially preventing MITM if the Roundcube installation
   * is configured to use HTTPS.
   *
   * For more details see the following:
   *   http://tools.ietf.org/html/draft-shaw-openpgp-hkp-00
   *   http://sks-keyservers.net/
   *
   *    Please use http://pool.sks-keyservers.net as the source for this proxy
   */
  function hkp_search() {
    if(!isset($_POST['op']) || !isset($_POST['search'])) {
      return $this->rc->output->command(
        'plugin.pks_search',
        array('message' => "ERR: Missing param",
              'op' => htmlspecialchars($_POST['op'])));
        $op = "";
        $search = "";
    } else {
      $op = $_POST["op"];
      $search = $_POST["search"];
    }

    if($op != "get" &&
       $op != "index" &&
       $op != "vindex")
      return $this->rc->output->command(
        'plugin.pks_search',
        array('message' => "ERR: Invalid operation",
              'op' => htmlspecialchars($op)));

    if($op == "index") {
      $ch = curl_init();
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_URL, "http://pool.sks-keyservers.net:11371/pks/lookup?op=index&search={$search}");
      $result = curl_exec($ch);
      $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if($status == 200) {
        // TODO Fix search regex to match 32/64-bit str
        preg_match_all("/\/pks\/lookup\?op=vindex&amp;search=(.*)\">(.*)<\/a>/", $result, $m);

        if(count($m[0]) > 0) {
          $found = array();
          for($i = 0; $i < count($m[0]); $i++)
            $found[] = array($m[1][$i], $m[2][$i]);
          return $this->rc->output->command(
            'plugin.pks_search',
            array('message' => json_encode($found),
                  'op' => htmlspecialchars($op)));
        }
      } else {
        preg_match("/Error handling request: (.*)<\/body>/", $result, $m);
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => "ERR: " . htmlspecialchars($m[1]),
                'op' => htmlspecialchars($op)));
      }
    } elseif($op == "get") {
      if(preg_match("/^0x[0-9A-F]{8}$/i", $search)) {
        define("32_BIT_KEY", true);
        define("64_BIT_KEY", false);
      } elseif(preg_match("/^0x[0-9A-F]{16}$/i", $search)) {
        define("32_BIT_KEY", false);
        define("64_BIT_KEY", true);
      } else {
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => "ERR: Incorrect search format for this operation",
                'op' => htmlspecialchars($op)));
      }

      $ch = curl_init();
      curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
      curl_setopt($ch, CURLOPT_URL, "http://pool.sks-keyservers.net:11371/pks/lookup?op=get&search={$search}");
      $result = curl_exec($ch);
      $status = curl_getinfo($ch, CURLINFO_HTTP_CODE);
      curl_close($ch);

      if($status == 200) {
        preg_match_all("/-----BEGIN PGP PUBLIC KEY BLOCK-----(.*)-----END PGP PUBLIC KEY BLOCK-----/s", $result, $m);
        return $this->rc->output->command(
          'plugin.pks_search',
          array('message' => json_encode($m),
                'op' => htmlspecialchars($op)));
      }
    }
  }

  /**
   * Handler for preferences_sections_list hook.
   * Adds OpenPGP settings sections into preferences sections list.
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function preferences_sections_list($p)
  {
    $p['list']['openpgp'] = array(
      'id' => 'openpgp',
      'section' => $this->gettext('openpgp'),
    );

    return $p;
  }

  /**
   * Handler for preferences_list hook.
   * Adds options blocks into OpenPGP settings sections in Preferences.
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function preferences_list($p) {
    if ($p['section'] != 'openpgp') {
      return $p;
    }

    $no_override = array_flip((array)$this->rc->config->get('dont_override'));

    $p['blocks']['openpgp']['name'] = $this->gettext('mainoptions');

    // always encrypt messages
    if (!isset($no_override['encrypt'])) {
      $field_id = 'rcmfd_encrypt';
      $encrypt = new html_checkbox(array('name' => '_encrypt', 'id' => $field_id, 'value' => 1));
      $p['blocks']['openpgp']['options']['encrypt'] = array(
        'title' => html::label($field_id, Q($this->gettext('always_encrypt'))),
        'content' => $encrypt->show($this->rc->config->get('encrypt', true)?1:0),
      );
    }

    // always sign messages
    if (!isset($no_override['sign'])) {
      $field_id = 'rcmfd_sign';
      $sign = new html_checkbox(array('name' => '_sign', 'id' => $field_id, 'value' => 1));
      $p['blocks']['openpgp']['options']['sign'] = array(
        'title' => html::label($field_id, Q($this->gettext('always_sign'))),
        'content' => $sign->show($this->rc->config->get('sign', true)?1:0),
      );
    }

    // automatically attach public key to messages
    if (!isset($no_override['attach_public_key'])) {
      $field_id = 'rcmfd_attach_public_key';
      $attach_public_key = new html_checkbox(array('name' => '_attach_public_key', 'id' => $field_id, 'value' => 1));
      $p['blocks']['openpgp']['options']['attach_public_key'] = array(
        'title' => html::label($field_id, Q($this->gettext('attach_public_key'))),
        'content' => $attach_public_key->show($this->rc->config->get('attach_public_key', true)?1:0),
      );
    }

    // warn on sending an unencrypted message
    if (!isset($no_override['warn_on_unencrypted'])) {
      $field_id = 'rcmfd_warn_on_unencrypted';
      $warn_on_unencrypted = new html_checkbox(array('name' => '_warn_on_unencrypted', 'id' => $field_id, 'value' => 1));
      $p['blocks']['openpgp']['options']['warn_on_unencrypted'] = array(
        'title' => html::label($field_id, Q($this->gettext('warn_on_unencrypted'))),
        'content' => $warn_on_unencrypted->show($this->rc->config->get('warn_on_unencrypted', true)?1:0),
      );
    }
    return $p;
  }

  /**
   * Handler for preferences_save hook.
   * Executed on OpenPGP settings form submit.
   *
   * @param array Original parameters
   * @return array Modified parameters
   */
  function preferences_save($p) {
    if ($p['section'] == 'openpgp') {
      $p['prefs'] = array(
        'encrypt'             => get_input_value('_encrypt', RCUBE_INPUT_POST) ? true : false,
        'sign'                => get_input_value('_sign', RCUBE_INPUT_POST) ? true : false,
        'attach_public_key'   => get_input_value('_attach_public_key', RCUBE_INPUT_POST) ? true : false,
        'warn_on_unencrypted' => get_input_value('_warn_on_unencrypted', RCUBE_INPUT_POST) ? true : false,
      );
    }

    return $p;
  }

  /**
   * Handler for message_compose hook
   * Attaches dummy public key
   * 
   * @param array Original parameters
   * @return array Modified parameters
   */
  function attach_public_key($args) {
    if ($f = $this->write_public_key()) {
      $args['attachments'][] = array('path' => $f, 'name' => "pubkey.asc", 'mimetype' => "text/plain");
    }
    return $args;
  }

  /**
   * Handler for message_sent hook
   * Deletes the public key from the server
   */
  function delete_public_key($args) {
    $rcmail = rcmail::get_instance();
    $temp_dir = unslashify($rcmail->config->get('temp_dir'));
    $file = $temp_dir."/".md5($_SESSION['username']).".asc";
    if(file_exists($file)) {
      @unlink($file);
    }
  }

  /**
   * Writes public key to attachment file, on compose it writes a
   * dummy which is later replaced by the used public key.
   */
  function write_public_key() {
    $rcmail = rcmail::get_instance();
    $temp_dir = unslashify($rcmail->config->get('temp_dir'));
    // temporary directory exists
    if (!empty($temp_dir)) {
      $file = $temp_dir."/".md5($_SESSION['username']).".asc";
      if(file_exists($file)) {
        @unlink($file);
      }
      
      // write public key
      $content = ' ';
      $publicKey = trim(get_input_value('_publickey', RCUBE_INPUT_POST));
      if ($publicKey != '') {
        $content = $publicKey;
      }
      if (file_put_contents($file, $content)) {
        return $file;
      }
    }
    return false;
  }
}
