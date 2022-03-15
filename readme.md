# Network SSO Client

See the Vanilla PHP
implementation for full documentation.

**Important Note**

Make sure your Session cookies and any other important login information
have SameSite set to None.


# Network API

### Calling Remote APIs

To contact a remote API in the network, you will need a Bearer token. You can
get one from the NetworkSSO object by calling

`$token = $network_sso->getApiToken($user_id = null);`

This will return a token that you can add to an Authorization header e.g:

`$YourFavouriteHttpLibrary->addHeader('Authorization: Bearer '.$token);`

If you pass in a user ID this will be sent to the remote API. Check with them
whether that's expected or required.