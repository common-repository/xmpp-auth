<?php
/*
    Copyright (C) 2011 Jehan Pagès (IM: xmpp:hysseo@zemarmot.net)
    [ No email contact, but you can send message through Instant Messaging,
    and you are not force to add my presence for this.
    You can also just send a normal message. I try to answer every message. ]

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program (file LICENSE at the root of the source archive). 
    If not, see <http://www.gnu.org/licenses/>.
*/

/****** LOGIN-related functions. *******/

$configuration = get_option('imauth_configuration');
if ($configuration &&
    (!isset($configuration['disable_login']) || !$configuration['disable_login'])):

function imauth_login_init()
{
	wp_enqueue_script('jquery');
	wp_enqueue_script('xmpp-auth-login',
	 // WP_PLUGIN_URL . '/someplugin/js/newscript.js', // old way, not SSL compatible
	  plugins_url('/login.js', __FILE__));
	wp_localize_script( 'xmpp-auth-login', 'objectL10n', array(
				'auth_id' => __('Authentication Identifier', 'xmpp-auth'),
				'conf_hide' => __('[Hide]', 'xmpp-auth'),
				'conf_show' => __('[Display]', 'xmpp-auth'),
				) );
}

add_action('login_init', 'imauth_login_init');

function imauth_login_checkbox()
{
  $imauth = ! empty($_POST['imauth']);
  $transaction_id = substr(base64_encode(random_bytes(4)), 0, 6);

  echo '<p id="imauth_transaction_id_p" ';
  if (!$imauth)
    echo 'style="display:none;"';
  echo '><label id="imauth_transaction_id_label">'
    . __('Authentication Identifier (Instant Messaging log-in only)', 'xmpp-auth') . '</label>'
    . '<br /><strong><label id="transaction_id_shown">'
    . $transaction_id . '</label></strong>'
    . '<input type="hidden" name="transaction_id" id="transaction_id" value="'
    . $transaction_id . '"/></p><br/>';

  echo '<p class="forgetmenot"><label><input name="imauth" type="checkbox" id="imauth" value="forever" tabindex="90"'
    . ($imauth? " checked='checked'":'') . ' onclick="updateLoginPage();" /> '
    . esc_attr(__('Via Instant Messaging', 'xmpp-auth')) . '&nbsp;</label></p>';

  echo '<script type="text/javascript">
    updateLoginPage();
  </script>';
}

add_action('login_form', 'imauth_login_checkbox');

function imauth_login_route($user, $username)
{
    if (is_a($user, 'WP_User'))
        return $user;

    global $configuration;
	if (!isset($error))
		$error = new WP_Error();

	$userinfo = get_userdatabylogin($username);

	if (!isset($_POST['imauth']) || empty($_POST['imauth']))
	{
        if ($userinfo)
        {
            $user_configuration = get_option('imauth_configuration_user_' . $userinfo->ID);
            if (isset($user_configuration['login_with']) && !in_array($user_configuration['login_with'], array('all', 'pwd')))
            {
                $error->add('unauthorized', __('<strong>ERROR</strong>: this user forbad authentication by password.', 'xmpp-auth'));
                return $error;
            }
        }
		add_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
		return $user;
	}
	if (empty($username))
	{
		$error->add('empty_username', __('<strong>ERROR</strong>: The username field is empty.', 'xmpp-auth'));
		return $error;
	}
	if (empty($_POST['transaction_id']))
	{
		// Section 4.3 of XEP-0070: "transaction identifier SHOULD be provided by the human user who controls the HTTP Client."
		// I could though generate one from here instead, but I prefer this to be controlled by the user,
		// unless the web browser, hopefully in the future, includes IM control.
		$error->add('empty_transaction', __('Provide a Transaction ID of your choice.', 'xmpp-auth'));
		return $error;
	}

    require_once(dirname(__FILE__) . '/xmpp_utils.php');
	if (!$userinfo || empty($userinfo->jabber)
		|| !imauth_valid_jid($userinfo->jabber))
	{
		// On purpose I make 2 errors in one, not to leak too easily existence of a user or of a JID.
		$error->add('invalid_jid', __('<strong>ERROR</strong>: invalid user. Either the user does not exist, you have not set a JID in your profile or you disabled IM login in your profile.', 'xmpp-auth'));
		return $error;
	}

	$user_configuration = get_option('imauth_configuration_user_' . $userinfo->ID);
    if (isset($user_configuration['login_with']) && !in_array($user_configuration['login_with'], array('all', 'im')))
	{
		// On purpose same error again, for configuration leak protection.
		$error->add('invalid_jid', __('<strong>ERROR</strong>: invalid user. Either the user does not exist, you have not set a JID in your profile or you disabled IM login in your profile.', 'xmpp-auth'));
		return $error;
	}

	// I have my own time limit system, so I deactivate the PHP one.
	// It avoids a ugly PHP error on the page and is handed nicely by Wordpress error system.
	set_time_limit(0); // TODO: shouldn't this be inside xmpp_stream?
    $xs = NULL;
    if (!empty($configuration['component']))
    {
        require_once(dirname(__FILE__) . '/xmpp_component.php');
        $xs = new xmpp_component($configuration['component'], $configuration['component_secret'],
                $configuration['component_server'], $configuration['component_port']);
    }
    else
    {
        require_once(dirname(__FILE__) . '/xmpp_stream.php');
        $xs = new xmpp_stream ($configuration['node'],
                $configuration['domain'], $configuration['password'],
                'bot', $configuration['server'], $configuration['port']);
    }

	if (!$xs->log ())
	{
		$error->add('xmpp_connect', __('<strong>ERROR</strong>: connection issue occurred.', 'xmpp-auth'));
		return $error;
	}

    include_once(dirname(__FILE__) . '/xmpp_stanzas.php');
    include_once(dirname(__FILE__) . '/xmpp_callbacks.php');
    $params = array(
        'from' => $userinfo->jabber,
        'transaction_id' => $_POST['transaction_id'],
        'thread' => time () . rand (), // Is it random enough? Probably for such use...
        'url' => get_site_url(),
        'method' => 'POST'
        );
    /*$xs->raw_send("<iq from='$xs->jid' id='hu2bac18' type='get'><query xmlns='jabber:iq:roster'/></iq>");
    $xs->raw_send('<presence/>');*/
    $auth_message = http_auth($xs->jid, $userinfo->jabber, get_site_url(), 'POST',
        $params['transaction_id'], $params['thread'],
		sprintf(__("Someone (maybe you) has requested access to \"%s\" (%s).\n", 'xmpp-auth'), get_bloginfo('name'), get_site_url()));
    $xs->add_callback('http_auth_cb', $params);
    if ($auth_message && $xs->raw_send($auth_message) && $xs->run())
	{
		$user =  new WP_User($userinfo->ID);
		//if (! empty($_POST['rememberme']))
		//	$remember = $_POST['rememberme'] ? true : false;
		// else
		//	$remember = false;
		//wp_set_auth_cookie($user->ID, $remember, $secure_cookie); // secure cookie?
        $xs->quit();
		return $user;
	}
	else
	{
		$error->add('xmpp_refused', __('<strong>ERROR</strong>: authentication has been refused or timed-out.', 'xmpp-auth'));
        $xs->quit();
		return $error;
	}
}

// I remove the "normal authentication" hook and will call it myself from my own hook.
remove_filter('authenticate', 'wp_authenticate_username_password', 20, 3);
// I want my rerouting to be made at pretty high priority and only 2 parameters are needed (password does not matter).
add_filter('authenticate', 'imauth_login_route', 0, 2);
endif;

function xmppauth_check_error_codes($codes)
{
    $codes[] = 'invalid_jid';
    $codes[] = 'xmpp_connect';
    $codes[] = 'xmpp_refused';
    $codes[] = 'empty_transaction';
    return $codes;
}

add_filter('shake_error_codes', 'xmppauth_check_error_codes', 10, 1);
?>
