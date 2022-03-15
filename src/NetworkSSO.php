<?php
namespace Twogether\NetworkSSO;

use Firebase\JWT\JWT;
use Twogether\LaravelURLSigner\Contracts\CacheBroker;
use Twogether\LaravelURLSigner\KeyFormatter;
use Twogether\LaravelURLSigner\KeyProviders\ArrayKeyProvider;
use Twogether\LaravelURLSigner\SignedUrlFactory;
use Twogether\NetworkSSO\Exceptions\InvalidPayload;

class NetworkSSO
{
    private $app_id;
    private $idp_host;
    private $private_key;
    private $urlSigner;
    private $cacheBroker;
    private $additional_login_parameters;

    public function __construct(
        string $app_id,
        string $idp_host,
        string $private_key,
        string $idp_public_key,
        CacheBroker $cacheBroker,
        array $additional_login_parameters = []
    )
    {

        $this->app_id = $app_id;
        $this->private_key = KeyFormatter::fromString($private_key,true);
        $this->idp_host = $idp_host;
        $this->cacheBroker = $cacheBroker;
        $this->additional_login_parameters = [];
        $this->urlSigner = new SignedUrlFactory(
            $this->app_id,
            $cacheBroker,
            new ArrayKeyProvider(['default' => [
                'public' => $idp_public_key,
                'private' => $private_key
            ]])
        );

        foreach($additional_login_parameters as $key => $value) {
            if($key !== 'login_url' && $key !== 'logout_url') {
                $key = "lp_".$key;
            }
            $this->additional_login_parameters[$key] = $value;
        }
    }

    public function getApiToken($user_id = null): string
    {
        $payload = [
            'iat' => time(),
            'exp' => time() + 60,
            'jti' => $this->cacheBroker->incr('network-api-request-nonce',5),
            'iss' => $this->app_id,
        ];

        if($user_id) {
            $payload['sub'] = $user_id;
        }

        return JWT::encode($payload,$this->private_key,'RS256');
    }

    public function getImpersonateUrl(string $return_to = null, bool $stop = false)
    {
        if(!$return_to) {
            $return_to = "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI'];
        }

        $url = $this->idp_host."/impersonate?return_to=".urlencode($return_to);
        if($stop) {
            $url .= "&stop=1";
        }
        return $url;
    }

    public function getStopImpersonatingUrl($return_to = null)
    {
        return $this->getImpersonateUrl($return_to, true);
    }

    public function loginRequiresReturn(array $params = null): bool
    {
        $params = $params ?? $_GET;
        return ($params['action'] ?? null) === 'refresh';
    }

    public function getLogoutUrl(string $user_agent = null)
    {
        return $this->getSignedUrl($this->getHostUrl("/sso/logout"),$user_agent,['action' => 'logout']);
    }

    public function getLoginReturnUrl(string $user_agent = null)
    {
        return $this->getSignedUrl($this->getHostUrl("/sso/refresh"),$user_agent,['action' => 'refresh-complete']);
    }

    public function getLoginUrl(string $user_agent = null)
    {
        return $this->getSignedUrl($this->getHostUrl("/sso/login"),$user_agent,array_merge($this->additional_login_parameters,['action' => 'login']));
    }

    public function getLogoutConfirmationUrl(string $user_agent = null)
    {
        return $this->getSignedUrl($this->getHostUrl("/sso/logout"),$user_agent,['action' => 'logout-complete']);
    }

	public function getRemoteLoginUrl($user_id,string $return_to = null,$strategy = null): string
	{
		return $this->getSignedUrl($this->getHostUrl('/remote-login'),null,[
			'uid' => $user_id,
			'strategy' => $strategy,
			'return_to' => $return_to,
		]);
	}
    public function validateUrl(string $url = null)
    {
        $this->urlSigner->validate($url ?: "https://".$_SERVER['HTTP_HOST'].$_SERVER['REQUEST_URI']);
    }

    public function getPayload(string $payload): array
    {
        $payload = json_decode($payload);

        try {

            // First decrypt the key

            openssl_private_decrypt(
                base64_decode($payload->encrypted_key),
                $decrypted_key,
                $this->private_key
            );

            // Now use the key and the cipher information to decrypt the payload

            $decrypted = openssl_decrypt(
                $payload->payload,
                $payload->cipher,
                $decrypted_key,
                0,
                base64_decode($payload->iv),
                base64_decode($payload->tag)
            );


            $payload = json_decode($decrypted,true);

            if(!$payload) {
                throw new InvalidPayload;
            }

        } catch(\Exception $e) {
            throw new InvalidPayload;
        }

        return $payload;

    }

    private function getHostUrl(string $path)
    {
        return trim($this->idp_host,' /').$path;
    }

    private function getSignedUrl(string $base, $user_agent, $parameters = [])
    {
        if(!$user_agent) { $user_agent = trim($_SERVER['HTTP_USER_AGENT']); }
        if(!$user_agent) { $user_agent = trim($_SERVER['HTTP_USER_AGENT'] ?? ''); }
        $base = $base . (strpos($base,"?") === false ? '?' : '&').'ua='.sha1($user_agent);

        $url = $this->urlSigner->make($base)
            ->withSource($_GET['return_id'] ?? $this->app_id);

        foreach($parameters as $key => $value) {
            $url->withParameter($key,$value);
        }

        return $url->get();
    }
}
