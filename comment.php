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

/******* COMMENTING-related functions *********/

$configuration = get_option('imauth_configuration');

function xmppauth_comment_form_fields($fields)
{
  global $configuration;
  $jid_validate = $configuration && isset($configuration['disable_comment']) && ! $configuration['disable_comment'];

  $comment_author_jid = isset($_COOKIE['comment_author_jid_' . COOKIEHASH]) ? $_COOKIE['comment_author_jid_' . COOKIEHASH] : '';
  $transaction_id = substr(base64_encode(random_bytes(4)), 0, 6);

  // XXX: I use the email class as it won't display well for some theme (example: twentyeleven) if there is no.
  // XXX: the aria-required parameter is apparently for screen readers. Good for accessibility.
  $fields['jid'] = '<p class="comment-form-email"><label for="jid" title="Jabber ID (will not be published)">'
    . __('Instant Messaging address', 'xmpp-auth')
    . ($jid_validate? ' <span class="required">*</span>' : '')
    . '</label>'
    . '<input id="jid" name="jid" type="text" value="' . $comment_author_jid . '" size="30" aria-required="true" />'
    . '<p><strong>Comment ID: ' . $transaction_id . '</strong></p>'
    . '<input type="hidden" name="transaction_id" id="transaction_id" value="'
    . $transaction_id
    .'"/></p>';
  return $fields;
}

add_filter('comment_form_default_fields', 'xmppauth_comment_form_fields', 10, 1);

function xmppauth_validate_comment($approved, $commentdata)
{
    global $configuration;

    /* If commenter authentication is deactivated, I don't do a thing. */
    if (! $configuration                           ||
        ! isset($configuration['disable_comment']) ||
        $configuration['disable_comment']);
        return $approved;

    /* Don't change a comment previously disapproved by another system
     * nor a comment from a registered user. */
    if ($approved === 'spam' ||
        $approved === 'trash' ||
        is_user_logged_in())
      return $approved;

	$comment_content = $commentdata['comment_content'];
	// For now I will simply disapprove a comment.
	// I wonder if I should not directly trash it (return "trash" instead of false).
    require_once(dirname(__FILE__) . '/xmpp_utils.php');
	if (!imauth_valid_jid($_POST['jid']))
		wp_die('<strong>' . __('Error:', 'xmpp-auth') , '</strong>'
            . __('please enter a valid JID. Your comment:', 'xmpp-auth')
            . '<br /><em>'. esc_attr($comment_content) . '</em>');

	set_time_limit(0); // TODO: shouldn't this be in my_socket?
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

	if (!$xs->log())
	{
		// XXX: it does not mean that the user's JID is wrong.
		//I don't save the comment when it happens.
		wp_die('<strong>' . __('Error:', 'xmpp-auth') . '</strong>'
		    . __('internal system error. Please retry later. Your comment:', 'xmpp-auth')
            . '<br /><em>' . esc_attr($comment_content) . '</em>');
	}

	// I use the comment content as transaction id.
    include_once(dirname(__FILE__) . '/xmpp_stanzas.php');
    include_once(dirname(__FILE__) . '/xmpp_callbacks.php');
    $params = array(
        'from' => $_POST['jid'],
        'transaction_id' => $_POST['transaction_id'],
        'thread' => time () . rand (), // Is it random enough? Probably for such use...
        'url' => get_permalink($commentdata['comment_post_ID']),
        'method' => 'POST'
        );
    $auth_message = http_auth($xs->jid, $_POST['jid'], get_permalink($commentdata['comment_post_ID']), 'POST',
        $params['transaction_id'], $params['thread'],
        sprintf(__("Someone (maybe you) is commenting on the website \"%s\" (%s)", 'xmpp-auth'), get_bloginfo('name'), get_site_url()),
        __('Comment ID', 'xmpp-auth'));
    $xs->add_callback('http_auth_cb', $params);
    if ($auth_message && $xs->raw_send($auth_message) && $xs->run(50))
	{
        $xs->quit();
        /* 1 means "approved". A comment which passes the XMPP auth
         * bypass normal validation. */
        return 1;
	}
	else
	{
        $xs->quit();
		// return "trash";
		wp_die('<strong>' . __('Error:', 'xmpp-auth') . '</strong>'
            . __('either the comment authentication has been refused or it timed-out.<br/>Are you sure your JID is valid? Your comment:', 'xmpp-auth')
            . '<br /><em>' . esc_attr($comment_content) . '</em>');
	}
}

// I want to be last on the list of approval.
add_filter('pre_comment_approved', 'xmppauth_validate_comment', 100, 2);

function xmppauth_save_comment_jid($comment_id)
{
	$jid = stripslashes(esc_attr($_POST['jid']));

	// See update_comment_meta.
	if (isset($_POST['jid']))
		add_comment_meta($comment_id, 'jid', $jid, true);

	$comment_cookie_lifetime = apply_filters('comment_cookie_lifetime', 30000000);
	setcookie('comment_author_jid_' . COOKIEHASH, $jid, time() + $comment_cookie_lifetime, COOKIEPATH, COOKIE_DOMAIN);
}

add_action('comment_post', 'xmppauth_save_comment_jid', 10, 1);

?>
