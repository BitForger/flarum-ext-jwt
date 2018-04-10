<?php
    /**
     * Created by PhpStorm.
     * User: noahkovacs
     * Date: 4/3/18
     * Time: 08:22
     * @soundtrack Still Alive - Red
     */

    namespace augustineinstitute\jwt\Middleware;


    use augustineinstitute\jwt\Util\Logger;
    use Exception;
    use Firebase\JWT\ExpiredException;
    use Firebase\JWT\JWT;
    use Flarum\Core\User;
    use Flarum\Http\CookieFactory;
    use Illuminate\Database\Eloquent\Collection;
    use InvalidArgumentException;
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Symfony\Component\HttpFoundation\Session\SessionInterface;
    use Zend\Diactoros\Response\JsonResponse;
    use Zend\Diactoros\Response\RedirectResponse;
    use Zend\Stratigility\MiddlewareInterface;
    use function explode;
    use function getenv;
    use function time;

    class AuthenticateWithJWT implements MiddlewareInterface
    {
        /**
         * @var Logger $logger
         */
        protected $logger;
        /**
         * @var $key string The key to decrypt the token
         */
        private $key;
        /**
         * @var bool $enforce
         */
        private $enforce;
        /**
         * @var string $token
         */
        private $token;
        /**
         * @var string $prefix
         */
        private $prefix = 'Bearer ';

        /**
         * @var CookieFactory $cookieFactory
         */
        private $cookieFactory;

        /**
         * @var bool $isApi
         */
        private $isApi;

        /**
         * @var string $formedUrl
         */
        private $formedUrl;

        /**
         * @var string $communityUrl
         */
        private $communityUrl;

        /**
         * @var string $loginUrl
         */
        private $loginUrl;

        /**
         * AuthenticateWithJWT constructor.
         * @param string|null $token
         * @param bool $enforce
         * @param bool $isApi
         */
        public function __construct($token, bool $enforce, bool $isApi)
        {
            $this->logger = new Logger("flarum_jwt_ext");
            $this->token = $token;
            $this->enforce = $enforce;
//            $this->cookieFactory = $cookieFactory;
            $this->isApi = $isApi;
        }

        /**
         * Process an incoming request and/or response.
         *
         * Accepts a server-side request and a response instance, and does
         * something with them.
         *
         * If the response is not complete and/or further processing would not
         * interfere with the work done in the middleware, or if the middleware
         * wants to delegate to another process, it can use the `$out` callable
         * if present.
         *
         * If the middleware does not return a value, execution of the current
         * request is considered complete, and the response instance provided will
         * be considered the response to return.
         *
         * Alternately, the middleware may return a response instance.
         *
         * Often, middleware will `return $out();`, with the assumption that a
         * later middleware will return a response.
         *
         * @param Request $req
         * @param Response $res
         * @param null|callable $out
         * @return Response|JsonResponse|RedirectResponse
         */
        public function __invoke(Request $req, Response $res, callable $out = null)
        {
            $request = $req;
            $response = $res;
            $skip = false;
            $uri = $request->getServerParams()['REQUEST_URI'];
            $this->logger->notice($uri);
            if ($uri === '/api/token') {
                $skip = true;
            }
            
            if ($request->getMethod() === "OPTIONS") { // Skip strict check of token on pre-flight requests
                $skip = true;
            }

            if (!$skip) {
                $this->key = getenv("API_SECRET");
                $this->formedUrl = getenv('FORMED_BASE_URI');
                $this->communityUrl = getenv('FORUM_URL');

                $this->loginUrl = $this->formedUrl . "login?url=".$this->communityUrl.$uri;

                if (!$this->token) {
                    $this->getToken($request);
                }

                try {
                    if (!$this->isApi) {
                        /**
                         * @var SessionInterface $session
                         */
                        $session = $request->getAttribute('session'); // get session
                        $sessionValid = $this->checkSession($session); // verify that it is valid, if not then migrate to new one
                        if (!$sessionValid) {
                            $this->logger->debug('session not valid');
                            $request = $this->handleToken($request);

                            $request = $this->login($request);
                        }
                        else {
                            $this->logger->debug('session valid');
                            $request = $request->withAttribute('session', $sessionValid);
                        }
                    }
                    else {
                        $this->logger->debug('api route');
                        $request = $this->handleToken($request);
                    }

                } catch (ExpiredException $expiredException) {

                    $this->logger
                        ->error('Exception Caught: ', ['exception' => $expiredException->getMessage()]);
                    return $this->sendError();
                } catch (Exception $exception) {

                    $this->logger
                        ->error('Exception Caught: ', ['exception' => $exception->getMessage()]);
                    return $this->sendError();
                }
            }

            return $out ? $out($request, $response) : $response;
        }

        /**
         * @param Request $request
         * @return Request
         */
        private function login(Request $request)
        {
            $uid = $request->getAttribute('user')['uid'];
            /**
             * @var SessionInterface $session
             */
            $session = $request->getAttribute('session');
            if (!$session->has('uid')) {
                $session->set('uid', $uid);
            }

            $actor = $this->getActor($uid);
            if ($session) {
                $actor->setSession($session);
            }

            return $request;
        }

        /**
         * @param $uid
         * @return User|Collection
         */
        private function getActor(string $uid)
        {
            /**
             * @var User|Collection $a
             */
            $a = User::where('uid', $uid)->first();

            if ($a->exists) {
                $a->updateLastSeen()->save();
            }

            return $a;
        }

        private function verifyKeyAndToken(bool $isApi)
        {
            if ((!$this->token || $this->token === '') && $this->enforce) {
                if ($isApi) {
                    return new JsonResponse(['authorized' => false], 401);
                }
                else {
                    throw new InvalidArgumentException();
                }
            }

            if (!$this->key && $this->enforce) {
                if ($isApi) {
                    return new JsonResponse(['authorized' => false], 500);
                }
                else {
                    throw new InvalidArgumentException();
                }
            }

            return true;
        }

        /**
         * @param SessionInterface $session
         * @param int $attempts
         * @return SessionInterface|bool
         */
        private function checkSession(SessionInterface $session, $attempts = 0)
        {
            if ($session->isStarted()) {
                $metaBag = $session->getMetadataBag();
                $created = $metaBag->getCreated();
                $lifetime = $metaBag->getLifetime();
                $uid = $session->get('uid');
                if (time() > ($created + $lifetime) || !$uid) {
                    return false;
                }
            }
            return $session;
        }

        /**
         * Verify token and secret key, get UID from decrypted token,
         * place it and user on request
         * @param ServerRequestInterface $request
         * @return Request
         */
        private function handleToken(Request $request)
        {
            // Session doesn't exist so check JWT
            $valid = $this->verifyKeyAndToken($this->isApi);
            if ($valid) {
                $jwt = JWT::decode($this->token, $this->key, ['HS256']);

//                $newSession = $this->startSession($jwt->uid);
//                $request = $request->withAttribute('session', $newSession);
                $request = $request->withAttribute('user', ['uid' => $jwt->uid, 'jwt' => $this->token]);
                $request = $this->addUserToRequest($request, $jwt);
                return $request;
            }
            throw new InvalidArgumentException("Key and Token validation failed");
        }

        private function sendError()
        {
            if (!$this->isApi && $this->enforce) {
                return new RedirectResponse($this->loginUrl);
            }
            else {
                return new JsonResponse(['authorized' => false], 401);
            }
        }

        private function getToken(ServerRequestInterface $request)
        {
            $header = $request->getHeader("authorization");
            $headerValue = $header[0];
            $headerValueArray = explode(' ', $headerValue);
            $prefix = $headerValueArray[0];
            $t = $headerValueArray[1];
            if (trim(strtolower($this->prefix)) === trim(strtolower($prefix))) {
                $this->token = $t;
            }
        }

        private function addUserToRequest(Request $request, $jwt)
        {
            $request->withAttribute("user", ["jwt" => $this->token, "uid" => $jwt->uid]);

            $actor = $this->getActor($jwt->uid);
            return $request->withAttribute('actor', $actor);
        }
    }