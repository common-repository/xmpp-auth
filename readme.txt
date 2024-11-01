=== XMPP Authentication ===

Contributors: Jehan Hysseo
Donate link: http://libreart.info/en/donate
Tags: jabber, xmpp, xep-0070, authentication, comments
requires at least: 3.2.0
Tested up to: 4.4.1
Stable tag: 0.6

Allows users to authenticate without password via XMPP and for visitors to be
filtered by XMPP verification.

== Description ==

This plugin has two main features:

* any reader on your website can comment if one has an Instant Messaging
  address (XMPP protocol, otherwise called Jabber. A Gmail or a LiveJournal
  account for instance are such standard IM identifiers as well);
* a subscribed user (whatever its role) can authenticate with one's IM
  address if they set their IM address.

This plugin is still in experimental state but is usable.

= Detailed Process =

The authentication part is something like openID, except that it uses your
existing IM address: you ask for authentication on a website, and it pops-up a
confirmation via IM (that you can accept, or refuse).

Considering that the IM protocol (XMPP) is very secure,
all the infrastructure to securely exchange an authentication request is
there. No need to make any new account, no need a special client, nor a
identity third party provider, and that's really instantaneous (as *instant*
messaging) and more secure than HTTP or SMTP protocols.

= Spam Protection =

It adds an additional layer to protect against Spam by verifying an
identity using a very secure and modern protocol (XMPP), which also is instant,
hence much more reliable in any way than email for instance.

= Secure and Easy Login =

Many reasons to use such a plugin for login:

* not to have to remember a new password (password-login can be disabled in
your profile, on a per-user choice);
* you are in a very insecure environment (for instance a cybercafe) and consider
only your IM account to be a minimum securized. Or better, you run an IM
client on your smartphone (or a similar tool), so you would receive the query
on this personal item while never typing any kind of password on the insecure
platform where you log.
* And so on.

== Installation ==

**The easy way** is via your installed Wordpress's administration pages:

1. Click `Plugins` > `Add New`;
1. Search for `xmpp-auth`;
1. Find it in the displayed list;
1. Click `Install Now`.

**Alternatively**, here is the old "manual" version:

1. Upload the plugin archive to *wp-content/plugins/* directory on your Wordpress installation;
1. Uncompress it by keeping it in its own sub-directory called *xmpp-auth/*;
1. Activate the plugin through the 'Plugins' menu in Wordpress;
1. Configure the plugin through the appearing sub-menu `XMPP Authentication`
under the `Plugins` menu;
1. When aknowledging the configuration by pressing the `Update` button, login
will be tested (a connection will be attempted). If anything is wrong with
your configuration, you will be immediately informed.

**Once installed**, I would suggest to modify the configuration in *Settings* >
*Discussion* > uncheck *Comment author must fill out name and e-mail* as they
will be verified by XMPP (but the fields will stay if the user wants to add
them in).

Also the new comment field (for JID) is automatically displayed if you use a
recent theme (because it uses a function newly added since 3.0). If you don't
see the new field after activating, don't panick. 4 solutions:

1. the simpler: use a more recent theme. The default _twentyten_ and
_twentyeleven_ will work perfectly without doing anything;
1. if you don't want to change your theme, try to contact the theme writers
and ask them if they could not support the generic (and now "adviced")
`comment_form()` feature (they will understand);
1. you know PHP/HTML and want to do it fast: simply check the file
`comments.php` of your theme. and either replace the whole form by this
simpler function: `<?php comment_form(); ?>` yourself;
1. or if you want to do it manually, add the following code (can be modified,
but what matters obviously is the id of the input field):
`<p class="comment-form-email"><label for="jid" title="Jabber ID (will not be
published)"><?php _e( 'JID' ); ?></label><span class="required">*</span>
<input id="jid" name="jid" type="text" value="" size="30" aria-required="true" />
</p>`

My advice is **obviously** to go for the first and the second solutions. The
third one is really when you want to do this fast (but still you should report
this to the theme writers for them to update upstream) and the fourth is a
last resort if you have some very atypical comment form.

= dependencies =

* PHP > 5.1.0 (for function *stream_socket_enable_crypto*).

* **expat** library to parse XML (enabled with the `--with-xml`
option of the php compilation).

*Note for gentoo users*: you must set the 'xml' USE flag.

* **OpenSSL** (> 0.9.6) must be installed on the server and PHP must be built
with `--with-openssl`.

* *OPTIONAL*: if the plugin is installed on a BSD (Mac included),
in order to use the SRV records on the admin JID, which is the correct way of
resolving the server and port addresses for a domain, the *PEAR* extension
**NET_DNS** must be installed: `pear install NET_DNS` (Note that it will ask
to have php compiled with `mhash` option).
If it is installed on Windows, it is not anymore useful if you have PHP
5.3.0 or later installed (under this version of PHP, you should also install
the NET_DNS extension to benefit SRV records).
Linux servers do not need this extension to have SRV.

*Note for gentoo users*: you must set the 'mhash' USE flag.

= Working Platforms =

This script has been tested only currently on Wordpress 3.2.1 up to Wordpress
3.2.1 with PHP 5.3.5 up to PHP 5.3.8, running on a GNU/Linux 64 bits (Gentoo
Linux).
Hopefully it should work with other software versions (not for PHP4, because
of the TLS feature which is PHP5 specific. Yet if you are really interested
into PHP4 compatibility and if TLS is not required for your connection, just
ask me, I will try to make a compatibility layer), but I cannot guarantee.
Tell me please if you tried this successfully with another configuration so
that I update the known working platforms list.

At the opposite, if you find a bug or encounter an issue on some
configuration, don't hesitate to tell me, and I will try and fix it.

== Configuration ==

= Publishing Account =

This section contains the connection parameters of the account which will be
used as a wordpress bot. I would personnaly advice to create a dedicated account
just for it (you may also use your personal account of course, as the plugin's
bot will create a resource identifier unique for every connection) and to
configure it to refuse any contact and communication (as noone will have to
add it to one's roster, except you maybe for test or debugging purpose?).
The fields are:

* The bot address (bare jid form: mybotname@myserveraddress);
* the password.

= Advanced Connection Parameters =

By default xmpp-auth can use SRV records which is a recommended way to
advertize server and port from a domain name (see for instance
http://dns.vanrein.org/srv/ for details).

This is an advanced section in case your server does not use SRV AND uses a server
which is not the same as the domain from the jid or a port different from the
default one (5222).

Hence there will be very very few cases where you will have to fill this
section and if you don't understand all what I say here, just don't fill
anything there (if you fill even only one field, then it will be used instead
of SRV and default values).

The default values will be used if the fields are empty and no SRV is configured on
the Jabber server:

* the XMPP server (often the same as 'myseveraddress' of the jid);
* the XMPP port (usually 5222).

== Frequently Asked Questions ==

= Will it work with any web browser and any IM client? =

On the web side, the XEP-0070 uses RFC-2617, which is a common way to
authenticate to websites. On the XMPP-side, RFC-6120 and XEP-0070 have a nice
way for clients which do not understand a given feature for falling back into
a message to answer, as though it was a discussion.

So hopefully it "should" work in most case with not-too broken web browser or
IM client.
For IM clients, it should work (tested or reported by someone) with Psi,
Gajim, OneTeam… In particular, it is known not to work with Pidgin, Adium,
Swift, and the GoogleMail web interface.

= I get "Warning: require_once(Auth/SASL/DigestMD5.php)" or another similar warning =

You should check the Installation/dependencies section. Some PHP modules are
necessary. If you are administrator or have flexible administrators, this will
be very easily fixable (follow my instructions in the "dependencies" section).
If you use a public service, which did not install these dependencies by
default, and where you cannot have anything installed, then I am sorry but my
plugin unfortunately won't work for you (actually for PEAR modules, you may
add them by hand, as they are pure PHP. But you would need to be developers
for the manipulation).

= When configuring, I get: "Authentication failure: TLS negotiation failed." =

This means that your server uses TLS (and that's good!) but simply I did not
package the certificate of their CA into my plugin. Please just tell me (see
"Contacts" section) your server, I will check the CA and if it is an
acceptable one, I will add its certificate.

It may also mean that the server certificate is self-signed, which is really not
secure. If many servers are this way, I may consider adding an option to
force such connection, but I would prefer not. If this happens to you, I
would rather suggest you to change the server of your bot for one where
security matters.

= The new "JID" field does not appear in the comment form! =

You most probably use an outdated theme which does not use recent Wordpress
features about commenting (since 3.0). This is not a blocker. See the bottom
of the "Installation" tab. I provide the solutions to this issue.

== Screenshots ==

1. Visitor posts a comment and receive a confirmation request by pop-up through
one's IM client (here Psi+).
2. Configuration page.

== TODO ==

Features I am considering:

* check quickstart (http://xmpp.org/extensions/inbox/quickstart.html). In
particular, I should at least cache DNS lookups now.
* deactivate IM features when plugin not configured.
* For comments, use the IM avatar of the commenter instead of gravatar;
* Make various notifications usually done by email be done by IM instead (if
adequate);
* Display the comment's JID on the admin page (as we display the email
address, obviously only for administrators);
* Add Scram-* to SASL package;
* Make the generic XMPP part a PEAR package.
* Subscribe with XMPP JID.
* Login with JID or username (both possible).
* If password is disabled, it also cannot be resetted.
* Make user choose to receive password reset or other notification through IM
instead of email.

== XMPP Features ==

Full Secure XML Stream with:

* TLS (with real certificate verification, so confidentiality and
authentication);
* SASL (Digest-MD5, CRAM-MD5 and PLAIN only for now);
* SRV records "randomization" algorithm.

== Contacts ==

You can have some news about this plugin on [my freedom
haven](http://jehan.zemarmot.net "my public diary").
You can also drop me an instant message on "hysseo" at zemarmot.net.

Have a nice life!

== Changelog ==

= 0.6 =

- Fix comment validation.
- Comment validation through XMPP is now marked as "experimental".
  Though still functional, I find the user experience crappy. I will want to
  review this deeply before considering it in release state.
- Comment validation times out at 50 sec (was 30).
- Transaction IDs are 6 characters. This makes them easier to copy, even on
  smaller virtual keyboard (for instance to validate on your personal smartphone
  a login made on a third-party untrusted machine).

= 0.5 =

- Update SASL lib to Auth_SASL2 0.1.0.
- Fix Cacert root certificate.
- Add Let's Encrypt root certificate.
- Improving/experimenting the protocole from XEP-0070. It should be more
  user-friendly, while still staying secure.

= 0.4 =

- When login is disabled, login page look is not modified.
- When comments is disabled, I still display the JID field, but simply don't
  process anything and without the '*' of mandatory fields.
- Localization prepared and French localization available.
- DNS results are now cached. I use the ttl of records (maximum 1 week, as
  proposed in RFC-1035) and reorder cached data using failure and success
  knowledge.
- PEAR Auth_SASL coded is included in the plugin, hence the dependency is no more.
- A patch has been sent upstream for SCRAM support.

- After many years of inactivity, I fixed all the code and tested it against
  Wordpress 4.4.1.
- Root certificates were also updated.

= 0.3 =

- Profile page configuration: per-user choice to disable password, IM
  authentication, or use both.
- IPv6 support and better DNS integration.
- The core XMPP library has been rewritten in a much more robust, hence secure
  API. The current version had been started in 2008. My first XMPP experiment
  that I used for the plugin Jabber Feed (that I will probably soon merge with
  the current plugin) and the API was not very nice and could break more
  easily on some unexpected outputs.

= 0.2 =

- Admins have now possibility to deactivate the plugin on a per-feature basis.
- Experimental component support.
- "Jabber / Google Talk" in profile renamed to "Standard IM".

= 0.1.5 =

- TLS certificates were not properly configured.
- Various fixes.

= 0.1 =

Initial Release.
The plugin can be used to login as a user, or post comments as an unsubscribed
visitor.

== Upgrade Notice ==

= 0.4 =

French localization available. DNS cached for improved performance. SCRAM-* support added.

= 0.3 =

Users can now customize IM integration in their profiles. IPv6 support. Core
rewritten.

= 0.2 =

Per-feature deactivation allowed and experimental component support.

= 0.1.5 =

This version fixes TLS certificates (for encryption).
The previous version was likely failing to validate your server certificate,
hence connect.

= 0.1 =

Initial Release. Experimental version.
