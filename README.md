# Django Auth Service

Django application for authenticating and authorizing user sessions.

Designed to work in tandem with an Nginx server using the [auth_request module](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html)
to authorize access to resources, e.g. a web service or set of services in a cluster.
Authorization is handled by one or more middleware classes, which must be added to your deployment settings.
There are also a selection of middleware classes available to provide authentication.

See the below sections for details about how the app works and how it can be configured.

## Basic access control flow

To verify access to a resource, the auth service app's `/verify` endpoint can be queried with a resource specified
with the `next` query parameter or the `X-Origin-URI` request header.

Activated authorization middleware can then check this URL against whatever rules are in place on the server and
make a decision to allow or deny access to the resource.

Here is an example of how to pass a resource to the verify endpoint:

```
http://my-auth-host.example.com/verify/?next=http://my-requested-resource.example.com/
```

If this was an anonymous action, and an appropriate authentication middleware had been enabled, a login flow
may be triggered by a 401 response from the auth service. In such a case, the next step would be to query the `/login`
endpoint with the same resource:

```
http://my-auth-host.example.com/login/?next=http://my-requested-resource.example.com/
```

This time, the resource URL will be stored inside the Django session during a browser login flow, to be fetched
back by the `/callback` endpoint.

The following settings related to resource URL management can be adjusted to suit your deployment needs:

- `RESOURCE_URL_QUERY_KEY` - The URL query parameter used to set the requested resource, default `next`.
- `RESOURCE_URL_HEADER_KEY` - If not using a URL query parameter, this request header parameter can be used to set the resource, default `X-Origin-URI`.
- `RESOURCE_URL_SESSION_KEY` - The dictionary key used to store the resource inside the Django session during a login flow, default `resource_url`.

## Using with the Nginx auth_request module

For detailed information about using the auth_request module, see the [Nginx documentation page](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html).

Adding the Auth service's `/verify` endpoint to an Nginx server is relatively simple, assuming your auth service application is running on port `5000` of your `localhost`:

```python
# The verify endpoint gives a 200, 401 or 403 response to a request depending on authorization
location /verify {
    proxy_pass http://authservice/verify;
    proxy_pass_request_body off;

    proxy_set_header X-Original-URI $request_uri;
}
```

Notice that we have specified the resource with the `X-Origin-URI` header, informing the auth service of the resource we are attempting to authorize access to.

If authorization is not granted, and authentication is required, a `/login` endpoint can be configured similarly:

```python
# The login endpoint will authenticate a user with a configured OIDC server
location /login {
    proxy_pass http://authservice/login;
    proxy_pass_request_body off;

    proxy_set_header Host $host;
}
```

In this case, we are using the `next` query parameter to set the resource URL.

The next thing to do is to configure some secured path on the same server to enable authorization for:

```python
# Some application serving secured data
location /dataserver {
    proxy_pass http://dataserver;

    # Auth request configuration for this path
    auth_request /verify;
    # Extract the authenticated user's username
    auth_request_set $username $upstream_http_x_username;
    ...

    # Unauhenticated requests are redirected to the login endpoint
    error_page 401 = @error401;

    ...
}
```

Here we have added a simple `auth_request` call to our previously configured `/verify` endpoint. Once queried by Nginx, the request will either be allowed through (on an HTTP 200 response), or denied (401 or 403 response). Additionally, an `error_page` has been specified for 401 responses, to trigger a login.

We are also using the `auth_request_set` parameter to extract an authenticated user's username and store it for other purposes. See the [relevant documentation](http://nginx.org/en/docs/http/ngx_http_auth_request_module.html) for more options.

Finally, the 401 error can be configured:

```python
location @error401 {
    set $query '';
    if ($request_uri ~* "[^\?]+\?(.*)$") {
        set $query $1;
    }

    return 302 /login/?next=$scheme://$http_host$http_port$request_uri;
}
```

This initiates a redirect to the `/login` endpoint when a request requires authentication.

## Authentication settings

This section introduces the available authentication middleware classes. One of more of these classes can added to your Django deployment's `MIDDLEWARE`
settings, in any order, to provide a variety of different authentication methods to users.

- `authenticate.oauth2.middleware.BearerTokenAuthenticationMiddleware`

  Authenticates requests based on the presence of an [OAuth2](https://oauth.net/2/) Bearer Token.

  Requires the following settings:

  - `OAUTH_CLIENT_ID` - The ID of your OAuth2 client.
  - `OAUTH_CLIENT_SECRET` The secret associated with your OAuth2 client.
  - `OAUTH_TOKEN_URL` - An endpoint on the OAuth2 server used to fetch a token.
  - `OAUTH_TOKEN_INTROSPECT_URL` - The OAuth2 server's token introspection endpoint. Used to determine token validity.

- `authenticate.oidc.middleware.OpenIDConnectAuthenticationMiddleware`

  Authenticates requests using an OpenID Connect authentication flow.

  This middleware makes use of [Authlib](https://pypi.org/project/Authlib/). See the Authlib documentation for help with [configuration](https://docs.authlib.org/en/latest/client/django.html#configuration).

- `authenticate.cookie.middleware.CookieAuthenticationMiddleware`

  Authenticates requests based on the presence of an encrypted cookie generated by the [crypto-cookie](https://pypi.org/project/crypto-cookie/) package.

  Requires the following settings:

  - `ACCOUNT_COOKIE_NAME` - The name of the cookie.
  - `SECURITY_SHAREDSECRET` - The Base64 encoded secret used to encrypt the cookie.

## Authorization Settings

Similar to authentication middleware, authorization middleware are added to your Django deployment's `MIDDLEWARE` settings
to provide a variety of authorization methods for controlling access to resources.

- `authorize.middleware.saml.SAMLAuthorizationMiddleware`

  A middleware which queries a SAML authorization server to determine if a user is permitted access to the requested resource.

  This middleware requires an authorization service endpoint specified by the `AUTHORIZATION_SERVICE_URL` setting.

- `authorize.middleware.LoginAuthorizationMiddleware`

  A simple middleware that will authorize any request that has been successfully authenticated.

### Bybassing authorization

The `AUTHORIZATION_EXEMPT_FILTER` setting can be assigned a function used to determine whether a request is exempt from authorization. e.g.

  ```python
  def exempt_all(request):
      return True

  AUTHORIZATION_EXEMPT_FILTER = exempt_all
  ```
