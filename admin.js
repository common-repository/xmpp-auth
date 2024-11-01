/*
XMPP-Auth -- A Wordpress plugin to authenticate via XMPP.
Copyright (C) 2011 Jehan Pagès (IM: xmpp:hysseo@zemarmot.net)

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program (file LICENSE at the root of the source archive);
if not, write to the Free Software Foundation,
Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

function switchAdvancedConfiguration()
{
	if (jQuery('#xmppauth_advanced_conf:hidden').length)
	{
		jQuery('#xmppauth_display').text(objectL10n.conf_hide);
		jQuery('#xmppauth_advanced_conf').show('fast');
	}
	else
	{
		jQuery('#xmppauth_display').text(objectL10n.conf_show);
		jQuery('#xmppauth_advanced_conf').hide('fast');
	}
}

function switchComponentConfiguration(previous)
{
	if (jQuery('#xmppauth-component-conf:hidden').length)
	{
		jQuery('#component').val(previous);
		jQuery('#xmppauth-component-conf').show();
		jQuery('#xmppauth-bot-conf').hide();
	}
	else
	{
		jQuery('#xmppauth-component-conf').hide();
		jQuery('#component').val('');
		jQuery('#xmppauth-bot-conf').show();
	}
}

function updateProfile()
{
	if (jQuery('#xmppauth_login_with_im:selected').length)
	{
		jQuery('#password').hide();
	}
	else
	{
		jQuery('#password').show();
	}
}

function commenter_checked()
{
	if (jQuery('#disable_comment:checked').length)
	{
		jQuery('#please_disable_required_email').hide();
	}
	else
	{
		jQuery('#please_disable_required_email').show();
	}
}

commenter_checked()
