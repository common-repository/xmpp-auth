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

function updateLoginPage()
{
	if (jQuery('#imauth:checked').length)
	{
		//jQuery('#user_pass').attr('disabled', 'disabled');
		jQuery('#user_pass').parent().hide();
		jQuery('#imauth_transaction_id_label').text(objectL10n.auth_id);
		jQuery('#imauth_transaction_id_p').show();
	}
	else
	{
		//jQuery('#user_pass').removeAttr('disabled');
		jQuery('#user_pass').parent().show();
		jQuery('#imauth_transaction_id_p').hide();
	}
}

