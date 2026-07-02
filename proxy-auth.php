<?php
namespace Grav\Plugin;

use Grav\Common\Config;
use Grav\Common\Grav;
use Grav\Common\Plugin;
use Grav\Common\User\User;
use Grav\Common\Utils;

use Grav\Plugin\Login\Login;
use Grav\Plugin\Login\Events\UserLoginEvent;
use Grav\Common\Debugger;

class ProxyAuthPlugin extends Plugin {
    public static function getSubscribedEvents() {
        return [
            'onTwigSiteVariables'       => ['twigSiteVariables', 0],
            'onPluginsInitialized'      => ['onPluginsInitialized', 10000],
            'onUserLogout'              => ['userLogout', 1]
        ];
    }

    public static function getHeader($key, $default=NULL) {
        if(empty($key)) {
            return $default;
        }

        $key = 'HTTP_' . strtoupper(str_replace('-', '_', $key));

        if(array_key_exists($key, $_SERVER)) {
            return $_SERVER[$key];
        }

        return $default;
    }

    public function debug($message) {
        $this->grav['debugger']->addMessage($message, 'debug');
    }

    public function getLoginUrl() {
        $url = $this->config->get('plugins.proxy-auth.url.login', NULL);

        if(!empty($url)) {
            $url = str_replace('${CURRENT_URL}', $this->grav['uri']->url, $url);
        }

        return $url;
    }

    public function getLogoutUrl($redirectUrl = NULL) {
        $url = $this->config->get('plugins.proxy-auth.url.logout', NULL);

        if(!empty($url)) {
            $url = str_replace('${CURRENT_URL}', $this->grav['uri']->url, $url);
        }

        return $url;
    }

    public function twigSiteVariables() {
        $this->grav['twig']->login_url = $this->getLoginUrl();
    }

    public function onPluginsInitialized() {
        if ($this->isAdmin() && !$this->grav['config']->get('plugins.proxy-auth.enabled')) {
            return;
        }

        $this->checkRouteMapping();
        $this->checkAuthentication();
    }

    protected function checkRouteMapping() {
        $routeMappings = $this->config->get('plugins.proxy-auth.route_mapping', []);
        $baseRoute = $this->config->get('plugins.proxy-auth.route', '/login');
        
        if (empty($routeMappings)) {
            return;
        }

        $uri = $this->grav['uri'];
        $path = $uri->path();

        // Only process if the path starts with the base route
        if (!\Grav\Common\Utils::startsWith($path, $baseRoute)) {
            return;
        }

        foreach ($routeMappings as $mapping) {
            $group = $mapping['group'] ?? '';
            if (empty($group)) {
                continue;
            }
            
            $expectedRoute = rtrim($baseRoute, '/') . '/' . $group;
            
            if ($path === $expectedRoute) {
                $this->debug('Landed on mapped login route: ' . $expectedRoute);
                
                // Assign the single mapped group
                $user = $this->extractAndSaveUser([$group]);
                
                if (!empty($user)) {
                    $this->authenticate($user);
                    $redirect = $mapping['redirect'] ?? '/';
                    $this->grav->redirectLangSafe($redirect);
                } else {
                    $this->debug('User not authenticated via proxy on mapped route.');
                    
                    // Prevent 404 by returning a 401 Unauthorized response
                    header('HTTP/1.1 401 Unauthorized');
                    echo "401 Unauthorized: Proxy authentication failed or required headers missing.";
                    exit();
                }
            }
        }
    }

    public function checkAuthentication() {
        $this->debug('Checking for user authentication...');

        $user = $this->grav['user'] ?? null;

        if($user && $user->authenticated) {
            return;
        }

        $user = $this->extractAndSaveUser();
        $uri = $this->grav['uri'];
        $loginUrl = $this->getLoginUrl();
        $onLoginUrl = !empty($loginUrl) && $uri->path() == parse_url($loginUrl, PHP_URL_PATH);

        if(!empty($user)) {
            $this->grav['debugger']->addMessage($user, 'debug', false);
            $this->authenticate($user);
        } else if(Utils::startsWith($uri->path(), '/admin', false) && !$onLoginUrl) {
            if(!empty($loginUrl)) {
                $this->debug("No user authenticated but we're in admin so forcing authentication through " . $loginUrl);
                $this->grav->redirectLangSafe($loginUrl);
            }
        } else {
            $this->debug('No user authenticated by proxy.');
        }

        if($onLoginUrl) {
            $this->debug('Landed at login URL. Trying to redirect.');

            $redirectUrl = $uri->query('redirect');

            if(strlen(trim($redirectUrl)) != 0) {
                $this->grav->redirectLangSafe($redirectUrl);
            } else {
                $this->grav->redirectLangSafe("/");
            }
        }
    }

    public function extractUsernameFromHeaders() {
        $username = self::getHeader($this->config->get('plugins.proxy-auth.headers.username', 'X-Remote-User'));
        $usernameRegex = $this->config->get('plugins.proxy-auth.headers.username_regex');

        if (!empty($username) && !empty($usernameRegex)) {
            if (@preg_match($usernameRegex, $username, $matches)) {
                $username = count($matches) > 1 ? $matches[1] : $matches[0];
            }
        }

        return $username;
    }

    public function extractAndSaveUser($extraGroups = []) {
        $email = self::getHeader($this->config->get('plugins.proxy-auth.headers.email', 'X-Remote-Email'));
        $emailRegex = $this->config->get('plugins.proxy-auth.headers.email_regex');
        if (!empty($email) && !empty($emailRegex)) {
            if (@preg_match($emailRegex, $email, $matches)) {
                $email = count($matches) > 1 ? $matches[1] : $matches[0];
            }
        }

        if(empty($email)) {
            $this->debug('No email provided by proxy. Authentication failed.');
            return NULL;
        }

        $username = $this->extractUsernameFromHeaders();
        if(empty($username)) {
            $username = $email;
        }

        $this->debug('Proxy authenticated user is ' . $username . ' (Email: ' . $email . '). Loading user details...');

        $groupSeparator = $this->config->get('plugins.proxy-auth.groupSeparator' , ',');
        $required = $this->config->get('plugins.proxy-auth.required.groups', []);
        
        $displayName = self::getHeader($this->config->get('plugins.proxy-auth.headers.displayName', 'X-Remote-Display-Name'));

        $accounts = $this->grav['accounts'];
        $grav_user = $accounts->load($username);
        
        // If username cannot be found, fall back to email address if available
        $exists = $grav_user->exists();
        if (!$exists && !empty($email)) {
            $found_user = $accounts->find($email, ['email']);
            if ($found_user->exists()) {
                $grav_user = $found_user;
                $exists = true;
            }
        }

        $headerGroupsStr = self::getHeader($this->config->get('plugins.proxy-auth.headers.groups', 'X-Remote-Groups'), "");
        $groups = !empty($headerGroupsStr) ? explode($groupSeparator, $headerGroupsStr) : [];

        // Merge extra groups from route mapping
        if (!empty($extraGroups)) {
            $groups = array_unique(array_merge($groups, $extraGroups));
        }

        // Include existing groups from the user's profile for the required check
        $current_groups = $exists ? $grav_user->get('groups', []) : [];
        $check_groups = array_unique(array_merge($groups, $current_groups));

        if(!empty($required)) {
            $this->debug('User requires groups ' . implode(',', $required));

            if(empty($check_groups) || empty(array_intersect($check_groups, $required))) {
                $this->debug('User not authorized.');
                return NULL;
            }
        }

        $userdata = [
            'username' => $username,
            'language' => 'en',
            'access' => ['site' => ['login' => 'true']]
        ];

        if(!empty($displayName)) {
            $userdata['fullname'] = $displayName;
        }

        if(!empty($email)) {
            $userdata['email'] = $email;
        }

        // Set or update groups
        // We overwrite the groups with the current proxy/mapping groups
        // to prevent users from keeping old groups forever.
        if (!empty($groups)) {
            $userdata['groups'] = $groups;
        } else {
            // Keep existing if proxy provides none and mapping provides none
            $current_groups = $exists ? $grav_user->get('groups', []) : [];
            if (!empty($current_groups)) {
                $userdata['groups'] = $current_groups;
            }
        }

        // Give everyone who authenticates via proxy the basic right to log in to the admin panel
        $userdata['access']['admin']['login'] = 'true';

        // Grant super admin rights only if they are in the 'admin' group
        if (in_array('admin', $userdata['groups'] ?? [])) {
            $userdata['access']['admin']['super'] = 'true';
        } else {
            $userdata['access']['admin']['super'] = 'false';
            if ($exists && isset($grav_user->access['admin']['super'])) {
                $grav_user->undef('access.admin.super');
            }
        }

        $grav_user->merge($userdata);

        // Save Grav user
        $grav_user->save();

        $grav_user->set('authenticated', true);

        return $grav_user;
    }

    public function authenticate($user) {
        $this->grav['session']->user = $user;
        unset($this->grav['user']);
        $this->grav['user'] = $user;

        // Fire the Grav Login Event so Admin and other plugins recognize the session
        if (class_exists('\Grav\Plugin\Login\Events\UserLoginEvent')) {
            $event = new \Grav\Plugin\Login\Events\UserLoginEvent([
                'user' => $user,
                'options' => [],
                'status' => 'success'
            ]);
            $this->grav->fireEvent('onUserLogin', $event);
        }
    }

    public function userLogout() {
        $logoutUrl = $this->getLogoutUrl();

        $email = self::getHeader($this->config->get('plugins.proxy-auth.headers.email', 'X-Remote-Email'));
        if(!empty($logoutUrl) && (!empty($this->extractUsernameFromHeaders()) || !empty($email))) {
            $this->grav->redirectLangSafe($logoutUrl);
            $this->grav->shutdown();
        }
    }
}
