<?php
/*
Plugin Name: XMPP-Auth
Plugin URI: https://wordpress.org/plugins/xmpp-auth/
Description: Authentication to the website through Instant Messaging Authorization (XMPP XEP-0070).
Version: 0.6
Author: Jehan Hysseo
Author URI: http://girinstud.io
License: GPLv2+
*/

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

if (is_admin())
{
    // If first run.
    $certs_hashed = glob(dirname(__FILE__) . '/certs/*.0');
    if (empty($certs_hashed))
    {
        unset($certs_hashed);
        $pems = glob(dirname(__FILE__) . '/certs/*.pem');
        // TODO: readdir or opendir would be more memory efficient.
        foreach($pems as $cert)
        {
            $hash = shell_exec('openssl x509 -hash -noout -in "' . $cert . '"');
            if (!empty($hash))
                @symlink($cert, dirname(__FILE__) . '/certs/' . rtrim($hash) . '.0');
        }
    }
    require_once(dirname(__FILE__) . '/admin.php');
}
else
{
    require_once(dirname(__FILE__) . '/comment.php');
    require_once(dirname(__FILE__) . '/login.php');
}

//require_once(dirname(__FILE__) . '/plugged.php');

load_plugin_textdomain('xmpp-auth', false, basename(dirname(__FILE__)) . '/i18n/');

?>
