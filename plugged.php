<?php
/*
    Copyright (C) 2011 Jehan Pagès (IM: xmpp:hysseo@zemarmot.net)

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


if (!function_exists( 'get_avatar' )) :
/**
 * Retrieve the avatar for a user who provided a user ID or email address.
 *
 * @since 2.5
 * @param int|string|object $id_or_email A user ID,  email address, or comment object
 * @param int $size Size of the avatar image
 * @param string $default URL to a default image to use if no avatar is available
 * @param string $alt Alternate text to use in image tag. Defaults to blank
 * @return string <img> tag for the user's avatar
*/
function get_avatar($id_or_email, $size = '96', $default = '', $alt = false)
{
	if (!get_option('show_avatars'))
		return false;

	if (false === $alt)
		$safe_alt = '';
	else
		$safe_alt = esc_attr($alt);

	if (!is_numeric($size))
		$size = '96';

	$jid = '';
    $email = '';
	if (is_numeric($id_or_email))
    {
		$id = (int) $id_or_email;
		$user = get_userdata($id);
		if ($user)
        {
			$jid = $user->jabber;
			$email = $user->user_email;
        }
	}
    elseif (is_object($id_or_email))
    {
		// No avatar for pingbacks or trackbacks
		$allowed_comment_types = apply_filters( 'get_avatar_comment_types', array( 'comment' ) );
		if ( ! empty( $id_or_email->comment_type ) && ! in_array( $id_or_email->comment_type, (array) $allowed_comment_types ) )
			return false;

		if ( !empty($id_or_email->user_id) ) {
			$id = (int) $id_or_email->user_id;
			$user = get_userdata($id);
			if ($user)
            {
				$email = $user->user_email;
                $jid = $user->jabber;
            }
		}
        else
        {
            if (!empty($id_or_email->comment_author_email) )
            {
                $email = $id_or_email->comment_author_email;
            }
            $jid = get_comment_meta($id_or_email->id, 'jid', true);
        }
	}
    else
    {
		$email = $id_or_email;
        $user = get_user_by_email($email);
        if ($user)
        {
            $jid = $user->jabber;
        }
	}

	if (empty($default))
    {
		$avatar_default = get_option('avatar_default');
		if (empty($avatar_default))
			$default = 'mystery';
		else
			$default = $avatar_default;
	}

	if (!empty($email))
		$email_hash = md5(strtolower($email));

    if (!empty($jid))
		$jid_hash = md5(strtolower($email));
	if (is_ssl()) {
		$host = 'https://secure.gravatar.com';
	} else {
		if ( !empty($email) )
			$host = sprintf( "http://%d.gravatar.com", ( hexdec( $email_hash[0] ) % 2 ) );
		else
			$host = 'http://0.gravatar.com';
	}

	if ( 'mystery' == $default )
		$default = "$host/avatar/ad516503a11cd5ca435acc9bb6523536?s={$size}"; // ad516503a11cd5ca435acc9bb6523536 == md5('unknown@gravatar.com')
	elseif ( 'blank' == $default )
		$default = includes_url('images/blank.gif');
	elseif ( !empty($email) && 'gravatar_default' == $default )
		$default = '';
	elseif ( 'gravatar_default' == $default )
		$default = "$host/avatar/s={$size}";
	elseif ( empty($email) )
		$default = "$host/avatar/?d=$default&amp;s={$size}";
	elseif ( strpos($default, 'http://') === 0 )
		$default = add_query_arg( 's', $size, $default );

    require_once(dirname(__FILE__) . '/xmpp_utils.php');
    if (!empty($jid) && imauth_valid_jid($jid))
    {
        $out = $default;
        // For now let's say I accept only png, jpg and gif files.
        $files = glob(dirname(__FILE__) . '/avatars/' . $jid_hash . '{*.png,*.jpg,*.gif}');
        if (!empty($files))
        {
            $filename = basename($files[0]);
            $out = plugins_url('avatars/' . $filename, __FILE__);
        }
        else
        {
            // TODO: check if subscribed + subscribe + retrieve.
        }

		$avatar = "<img alt='{$safe_alt}' src='{$out}' class='avatar avatar-{$size} photo' height='{$size}' width='{$size}' />";
    }
	elseif (!empty($email))
    {
		$out = "$host/avatar/";
		$out .= $email_hash;
		$out .= '?s='.$size;
		$out .= '&amp;d=' . urlencode( $default );

		$rating = get_option('avatar_rating');
		if ( !empty( $rating ) )
			$out .= "&amp;r={$rating}";

		$avatar = "<img alt='{$safe_alt}' src='{$out}' class='avatar avatar-{$size} photo' height='{$size}' width='{$size}' />";
	}
    else
    {
		$avatar = "<img alt='{$safe_alt}' src='{$default}' class='avatar avatar-{$size} photo avatar-default' height='{$size}' width='{$size}' />";
	}

	return apply_filters('get_avatar', $avatar, $id_or_email, $size, $default, $alt);
}
endif;

?>
