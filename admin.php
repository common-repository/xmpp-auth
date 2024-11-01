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

/**
 * All Administration-related functions.
 */

function imauth_admin_init()
{
    wp_enqueue_style('xmpp-auth', plugins_url('/xmpp-auth.css', __FILE__));
	wp_enqueue_script('jquery');
	wp_enqueue_script('xmpp-auth-admin',
	 // WP_PLUGIN_URL . '/someplugin/js/newscript.js', // old way, not SSL compatible
	  plugins_url('/admin.js', __FILE__));
	wp_localize_script( 'xmpp-auth-admin', 'objectL10n', array(
				'auth_id' => __('Authentication Identifier', 'xmpp-auth'),
				'conf_hide' => __('[Hide]', 'xmpp-auth'),
				'conf_show' => __('[Display]', 'xmpp-auth'),
				) );
}
// TODO: actually I'd like to limit this one to the plugin configuration page.
// XXX: there are a wp_print_scripts/styles action, but they would load the scripts/styles all the time.
// I'll try and avoid this.
add_action('admin_init', 'imauth_admin_init');

/**********************\
// Configuration Page \\
\**********************/

function imauth_configuration_page () // {{{
{
	global $wpdb;
	add_option('imauth_configuration', array (), 'deprecated', 'yes');
	add_option ('imauth_transactions', array (), 'deprecated', 'yes'); // Running transactions not yet aknowledged.

	if (isset($_POST['update_configuration']))
	{
		require_once(dirname(__FILE__) . '/xmpp_stream.php');
		$configuration['node'] = strip_tags (trim($_POST['node']));
		$configuration['domain'] = strip_tags (trim ($_POST['domain']));
		$configuration['password'] = strip_tags (trim($_POST['password']));
        $configuration['component'] = strip_tags(trim($_POST['component']));
        $configuration['component_secret'] = strip_tags(trim($_POST['component_secret']));
        $configuration['component_server'] = strip_tags(trim($_POST['component_server']));
        $component_port = strip_tags(trim($_POST['component_port']));
		if (is_numeric ($component_port))
            $configuration['component_port'] = intval($component_port);
		else
			$configuration['component_port'] = '';

		$configuration['disable_login'] = isset($_POST['disable_login']);
		$configuration['disable_comment'] = isset($_POST['disable_comment']);

		$posted_server = strip_tags (trim($_POST['server']));

		$configuration['server'] = $posted_server;

		$posted_port = strip_tags (trim($_POST['port']));
		if (is_numeric ($posted_port))
			$configuration['port'] = intval ($posted_port);
		else
			$configuration['port'] = '';

        $xs = NULL;
        if (!empty($configuration['component']))
        {
            require_once(dirname(__FILE__) . '/xmpp_component.php');
            $xs = new xmpp_component($configuration['component'], $configuration['component_secret'],
                $configuration['component_server'], $configuration['component_port']);
        }
        else
            $xs = new xmpp_stream ($configuration['node'],
                    $configuration['domain'], $configuration['password'],
                    'bot', $configuration['server'], $configuration['port']);
		
		if ($xs->log ()
			&& $xs->quit ())
		{
			update_option('imauth_configuration', $configuration);
			echo '<div class="updated"><p>' . __('Configuration tested and saved', 'xmpp-auth') . '</p></div>';
		}
		else
			echo '<div class="updated"><p>' . __('Configuration not saved. The following error occured:<br />', 'xmpp-auth') . $xs->last_error . '</p></div>';
			
	}
	else
		// If we are just displaying the page or if we reset to last saved config, we first load up the options array.
		$configuration = get_option('imauth_configuration');

    $as_component = isset($configuration['component']) && !empty($configuration['component']);
	//now we drop into html to display the option page form.
	?>
	<div class="wrap">
		<h2><?php echo _e('IM configuration', 'xmpp-auth') ?></h2>
		<form method="post" action="">
			<fieldset
                <?php echo $as_component? "style='display:none'" : ''; ?>
                id='xmppauth-bot-conf' class="imauth-options">
				<legend onclick="switchComponentConfiguration('<?php echo $configuration['component']; ?>');"><?php _e('Bot Account', 'xmpp-auth'); ?> <a id="xmppauth_component"><?php _e('[Switch to Component]', 'xmpp-auth'); ?></a></legend>
				<p><label>
				<?php _e('Login (bare jid)', 'xmpp-auth') ?><br />
					<input name="node"
						type="text"
						id="node"
						value="<?php echo $configuration['node']; ?>"
						size="29" /></label>
				
				<label>@
					<input name="domain"
						type="text"
						id="domain"
						value="<?php echo $configuration['domain']; ?>"
						size="28" />
				</label></p>

				<p><label>
				<?php _e('Password', 'xmpp-auth') ?><br />
					<input name="password"
						type="password"
						id="password"
						value="<?php echo $configuration['password']; ?>"
						size="60" />
				</label></p>

                <fieldset class="imauth-advanced-options">
                    <legend onclick="switchAdvancedConfiguration();"><?php _e('Advanced Connection Parameters', 'xmpp-auth');?> <a id="xmppauth_display"><?php _e('[Display]', 'xmpp-auth'); ?></a></legend>
                    <div id="xmppauth_advanced_conf" style="display:none">
                            <p><em><?php _e("These are advanced settings. If you don't understand them, they are probably useless and default values will be enough.", 'xmpp-auth') ?> </em></p>
                        <?php 
                        if (class_exists ("NET_DNS_Resolver") || function_exists ("dns_get_record"))
                        {
                            ?>
                        <p><em><?php _e('Note that SRV Records will be used by default.', 'xmpp-auth') ?></em></p>
                        <?php
                        }
                        else
                        {
                            ?>
                            <p><em><?php _e('SRV Records discovery option is not enabled because the PEAR module NET_DNS is not installed on this server.', 'xmpp-auth') ?></em></p>
                            <?php
                        }
                ?>

                        <p><label>
                        <?php _e('Server', 'xmpp-auth') ?><br />
                            <input name="server"
                                type="text"
                                id="server"
                                value="<?php echo $configuration['server']; ?>"
                                size="60" />
                        </label></p>

                        <p><label>
                        <?php _e('Port', 'xmpp-auth') ?><br />
                            <input name="port"
                                type="text"
                                id="port"
                                value="<?php echo $configuration['port']; ?>"
                                size="60" />
                        </label></p>
                    </div>
                </fieldset>
			</fieldset>
			<fieldset
                <?php echo $as_component? '' : "style='display:none'"; ?>
                id='xmppauth-component-conf' class="imauth-options">
				<legend onclick="switchComponentConfiguration('<?php echo $configuration['component']; ?>');"><?php _e('Component Account', 'xmpp-auth'); ?> <a id="xmppauth_component"><?php _e('[Switch to Bot]', 'xmpp-auth'); ?></a></legend>
                <p><em><?php _e("Register as a component instead of using a bot. This requires you to run your own server and configure it. If you don't understand what is a component, this feature is probably not for you and you should come back on bot mode.", 'xmpp-auth') ?> </em></p>
                <p><strong><?php _e("NOTE: this is an experimental support. I suggest to use it for test, not for production.", 'xmpp-auth') ?> </strong></p>
				<p><label>
				<?php _e('Component bare jid', 'xmpp-auth') ?><br />
					<input name="component"
						type="text"
						id="component"
						value="<?php echo $configuration['component']; ?>"
						size="29" /></label></p>
				
				<p><label>
				<?php _e('Secret', 'xmpp-auth') ?><br />
					<input name="component_secret"
						type="password"
						id="component_secret"
						value="<?php echo $configuration['component_secret']; ?>"
						size="60" />
				</label></p>

				<p><label>
				<?php _e('Server', 'xmpp-auth') ?>
					<input name="component_server"
						type="text"
						id="component_server"
						value="<?php echo $configuration['component_server']; ?>"
						size="29" /></label>

				<label><?php _e('Port', 'xmpp-auth') ?>
					<input name="component_port"
						type="text"
						id="component_port"
						value="<?php echo $configuration['component_port']; ?>"
						size="29" /></label></p>
            </fieldset>

			<fieldset class="imauth-options">
				<legend><?php _e('Features', 'xmpp-auth');?></legend>
                <p><label><input name="disable_login" type="checkbox" id="disable_login" value="disable_login"
                <?php echo isset($configuration['disable_login']) && $configuration['disable_login']? 'checked="checked"' : ''; ?>
                /> <?php _e('Disable Login via XMPP', 'xmpp-auth'); ?></label></p>
                <p><label><input name="disable_comment" type="checkbox" id="disable_comment"
                                 value="disable_comment" onclick="commenter_checked()"
                <?php echo ! isset($configuration['disable_comment']) || $configuration['disable_comment']? 'checked="checked"' : ''; ?>
                /> <?php _e('Disable Commenters Authentication via XMPP', 'xmpp-auth');
                        echo ' ';
                         _e('(experimental feature)', 'xmpp-auth');?></label>
                <?php
                  if (get_option('require_name_email'))
                  {
                ?>
                <br />
                <label id="please_disable_required_email"
                <?php
                  if (! isset ($configuration['disable_comment']) ||
                      $configuration['disable_comment'])
                      echo 'style="display:none;"';
                ?>
                >
                Warning: commenting validation is an experimental feature.<br />
                Unless you want commenters to have to enter both the email and the
                jabber id, you should disable the option "<em>Comment author must
                fill out name and email</em>" under <a
                href="options-discussion.php">Settings &gt; Discussion</a></label>
                <?php
                  }
                ?>
                </p>
			</fieldset>

			<?php echo apply_filters('imauth_additional_configuration', ''); ?>

			<div class="submit">
				<input type="submit"
					name="update_configuration"
					value="<?php _e('Update', 'xmpp-auth') ?>"
					style="font-weight:bold;" />
				<input type="submit"
					name="reset_configuration"
					value="<?php _e('Reset', 'xmpp-auth') ?>"
					style="font-weight:bold;font-style:italic" />
			</div>
		</form>    		
	</div>
	<?php	
} // }}}

function imauth_menu () // {{{
{
	if (function_exists('current_user_can'))
	{
		if (!current_user_can('manage_options'))
			return;
	}
	else
	{
		global $user_level;
		get_currentuserinfo ();
		if ($user_level < 8)
			return;
	}
	if (function_exists ('add_submenu_page'))
		add_submenu_page('plugins.php', __('IM authentication', 'xmpp-auth'), __('XMPP Authentication', 'xmpp-auth'), 'edit_plugins', 'xmpp-auth-conf', 'imauth_configuration_page');
} // }}}

// Install the configuration page.
add_action ('admin_menu', 'imauth_menu');

/****** Admin notice *****/

$not_configured = !get_option('imauth_configuration');
function xmppauth_not_configured_notice()
{
	if (function_exists('current_user_can'))
	{
		if (!current_user_can('manage_options'))
			return;
	}
	else
	{
		global $user_level;
		get_currentuserinfo ();
		if ($user_level < 8)
			return;
	}
    echo "<div id='xmppauth-warning' class='updated fade'><p><strong>".__('XMPP Authentication is not configured yet!', 'xmpp-auth')."</strong> ".sprintf(__('You must <a href="%1$s">configure it</a> for it to work.', 'xmpp-auth'), "plugins.php?page=xmpp-auth-conf")."</p></div>";
}
if ($not_configured)
    add_action('admin_notices', 'xmppauth_not_configured_notice');

/******************** Profile Page *************************/

function rename_jabber_label($current)
{
    return __('Instant Messaging (Jabber / Gmail / LiveJournal…)', 'xmpp-auth');
}

add_filter('user_jabber_label', 'rename_jabber_label', 30, 1);

function modify_user_contact_methods ($user_contact)
{
  /* Add Jabber as a user contact method. */
  $user_contact['jabber'] = __('Instant Messaging (Jabber/XMPP, used for authentication)');

  return $user_contact;
}
add_filter('user_contactmethods', 'modify_user_contact_methods');

function xmppauth_profile_personal_options($user)
{
	$configuration = get_option('imauth_configuration');
    if (isset($configuration['disable_login']) && $configuration['disable_login'])
        return;

	$user_configuration = get_option('imauth_configuration_user_' . $user->ID);
    $login_with = 'all';
    $im_notification = true;
    if ($user_configuration)
    {
        $login_with = $user_configuration['login_with']; // Can be 'im', 'pwd', 'all'
        $im_notification = $user_configuration['notification'];
    }
    // Stupid I cannot reuse the existing table, but the personal page is out of it!
    // So I make a new one.
?>
<table class="form-table">
    <tr>
        <th><label for="xmppauth_login_with"><?php _e('Allow login with', 'xmpp-auth') ?></label></th>
        <td>
            <select name="xmppauth_login_with" id="xmppauth_login_with" onclick="updateProfile();">
                <option id="xmppauth_login_with_all"<?php selected($login_with, 'all'); ?> value="all"><?php _e('IM and Password', 'xmpp-auth'); ?></option>
                <option id="xmppauth_login_with_im"<?php selected($login_with, 'im'); ?> value="im"><?php _e('IM only', 'xmpp-auth'); ?></option>
                <option id="xmppauth_login_with_pwd"<?php selected($login_with, 'pwd'); ?> value="pwd"><?php _e('Password Only', 'xmpp-auth'); ?></option>
            </select>
        </td>
    </tr>
<?php /* TODO
    <tr>
		<th scope="row"><?php _e('Notifications')?></th>
		<td><label for="xmppauth_im_notifications"><input name="xmppauth_im_notifications" type="checkbox" id="xmppauth_im_notifications" value="true" <?php checked(true, $im_notification); ?> /> <?php _e('Notify by IM (instead of emails)'); ?></label></td>
        </td>
    </tr>*/ ?>
</table>
<?php
}
add_action('profile_personal_options', 'xmppauth_profile_personal_options', 10, 1);

function xmppauth_bottom_profile()
{
?>
<script type="text/javascript">
    updateProfile();
</script>';
<?php
}
add_action('show_user_profile', 'xmppauth_bottom_profile');

function xmppauth_personal_options_update($user_id)
{
	$configuration = get_option('imauth_configuration');
    if (isset($configuration['disable_login']) && $configuration['disable_login'])
        return;

	$user_configuration = get_option('imauth_configuration_user_' . $user_id);
    if (!isset($user_configuration))
        $user_configuration = array();

    if (isset($_POST['xmppauth_login_with']) && in_array($_POST['xmppauth_login_with'], array('all', 'im', 'pwd')))
        $user_configuration['login_with'] = $_POST['xmppauth_login_with'];
    else
        $user_configuration['login_with'] = 'all';

    $user_configuration['notification'] = isset($_POST['xmppauth_im_notifications']);

    update_option('imauth_configuration_user_' . $user_id, $user_configuration);
}

add_action('personal_options_update', 'xmppauth_personal_options_update', 10, 1);

/*
// This feature is nicer with Javascript.
function xmppauth_show_password_fields($show, $user)
{
	$configuration = get_option('imauth_configuration');
    if (isset($configuration['disable_login']) && $configuration['disable_login'])
        return true;

	$user_configuration = get_option('imauth_configuration_user_' . $user->ID);
    if (isset($user_configuration['login_with']) && $user_configuration['login_with'] == 'im')
        return false;
    else
        return true;
}

add_filter('show_password_fields', 'xmppauth_show_password_fields', 10, 2);*/

/******************* Plugins Page ************/

function xmppauth_plugin_action_links($actions, $plugin_file )
{
	if ($plugin_file == plugin_basename(dirname(__FILE__) .'/xmpp-auth.php' ))
    {
		$actions['settings'] = '<a href="plugins.php?page=xmpp-auth-conf">'.__('Settings', 'xmpp-auth').'</a>';
	}

	return $actions;
}

add_filter('plugin_action_links', 'xmppauth_plugin_action_links', 10, 2 );

?>
