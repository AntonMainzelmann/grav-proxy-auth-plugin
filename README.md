# Grav Proxy Authentication Plugin

This plugin adds the ability to authenticate users
by an upstream proxy server that properly sets HTTP headers.

> It's **very** important that the proxy also scrub
> the headers it will be setting so malicious users
> cannot just set headers on their request and bypass
> the proxy login.

## Installation

The proxy authentication plugin depends on the login
and form plugins. It is fully compatible with **Grav 1.7** and **2.0**, taking advantage of Grav's Flex Objects for user management.

```
$ bin/gpm install proxy-auth
```

## Configuration

This plugin has several important configuration
options that control its behavior:

```yaml
enabled: true                                   # Enable the plugin

route: '/login'                                 # Base route for dynamic login mapping

route_mapping:                                  # Map specific login groups to redirects
  - group: 'admin'                              # Triggered at /login/admin
    redirect: '/admin'
  - group: 'editor'                             # Triggered at /login/editor
    redirect: '/admin'

headers:
  username: 'X-Remote-User'                     # HTTP header where the username can be found (optional, falls back to email).
  username_regex: '/(.*)/'                      # Optional regex to extract the username from the header
  displayName: 'X-Remote-Display-Name'          # HTTP header where the full name can be found.
  email: 'X-Remote-Email'                       # HTTP header where the e-mail address can be found (MANDATORY).
  email_regex: '/(.*@.*)/'                      # Optional regex to extract the email from the header
  groups: 'X-Remote-Groups'                     # HTTP header where user groups can be found.

groupSeparator: ','                             # Character used to separate multiple groups
required:
  groups: []                                    # Groups a user must have to be considered "authenticated" (one match is sufficient)
url:
  login:                                        # URL to which to send users when they need authentication.
  logout:                                       # URL to which to send users when they need to logout.
```

### Route Mapping (Grav 1.7+ Flex Users)
You can configure **Login Route Mappings** using a `route` base path (default: `/login`). This allows you to set up specific paths (e.g. `/login/admin` or `/login/editor`) that your proxy uses to pass users to Grav. When a user hits this path with valid proxy headers, the plugin will:
1. Create or load the user as a **Flex Object** in Grav.
2. Automatically assign the single group defined for this mapped route (e.g., `admin`).
3. Save the user physically to disk.
4. Redirect them to the configured destination (e.g., `/admin`).

The login and logout URLs will replace the string
`${CURRENT_URL}` with the absolute URL the user is on.
**Note**: For this to work properly, the hostname
sent by the proxy should be the external hostname of
the site or the correct hostname should be configured
in Grav's settings.

Also, the group header currently simply uses PHP's
`explode` function and therefore does not support
quoting.

## Usage

First, setup a reverse proxy that performs some kind
of authentication and sets, at least, an email
header. Authentication _will fail_ if the email is
missing. The username header is optional; if omitted,
the email address is used as the username. Users will
be unable to become super admins without the `admin` group.

The plugin supports group management in the
traditional Grav way, see [the documentation](https://learn.getgrav.org/advanced/groups-and-permissions).
At the very least, you will want to assign a group
the following two permissions to create an admin
group:

- admin.login
- admin.super

**Automatic Admin Access**:
Any user successfully authenticated by the proxy via this plugin is automatically granted basic `admin.login` access (allowing them to see the Grav admin dashboard).
If the user is assigned the `admin` group (by route mapping or proxy header), they are additionally granted `admin.super` access. If they lose the `admin` group, their `admin.super` access is automatically revoked on their next login.

You may have to modify your theme a bit to get
login/logout working. This plugin will set the `login_url`
and `logout_url` twig variables that you can use to get the correct URL
with which to logout/login.

## Caveats

- Only the `onPluginsInitialized` and `onUserLogout` events are caught by this plugin.
- User registration is not supported since that is
  expected to be handled by an external system.
- Forgotten password and any related functionality is not supported.
- Groups that contain the "group separator" will not
  work and will likely break horribly.
- Standard limitations of HTTP header sizes and values
  apply.
