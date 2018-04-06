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
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Symfony\Component\HttpFoundation\Session\Session;
    use Symfony\Component\HttpFoundation\Session\SessionInterface;
    use Zend\Diactoros\Response\JsonResponse;
    use Zend\Diactoros\Response\RedirectResponse;
    use Zend\Stratigility\MiddlewareInterface;
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
        public function __construct($token, $enforce, $isApi)
        {
            $this->logger = new Logger("flarum_jwt_ext");
            $this->token = $token;
            $this->enforce = $enforce;
//            $this->cookieFactory = $cookieFactory;
            $this->isApi = $isApi;
            $this->logger->debug('constructed');
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
         * @param Request $request
         * @param Response $response
         * @param null|callable $out
         * @return null|Response
         */
        public function __invoke(Request $request, Response $response, callable $out = null)
        {
            $this->logger->debug('invoked');
            $uri = $request->getServerParams()['REQUEST_URI'];
            $this->logger->notice($uri);
            if ($uri === '/api/token') {
                return $out ? $out($request, $response) : $response;
            }


            $this->key = getenv("API_SECRET");
            $this->formedUrl = getenv('FORMED_BASE_URI');
            $this->communityUrl = getenv('FORUM_URL');

            $this->loginUrl = $this->formedUrl . "login?url=".$this->communityUrl.$uri;

            if (!$this->token) {
                $header = $request->getHeaderLine("Authorization");
                $parts = explode(';', $header);

                if (isset($parts[0]) && starts_with($parts[0], $this->prefix)) {
                    $this->token = substr($parts[0], strlen($this->prefix));
                }
            }

            try {
                $this->logger->debug('trying to run');
                if (!$this->isApi) {
                    $this->logger->debug('not api route');
                    /**
                     * @var SessionInterface $session
                     */
                    $session = $request->getAttribute('session'); // get session
                    $sessionValid = $this->checkSession($session); // verify that it is valid, if not then migrate to new one
                    if (!$sessionValid) {
                        $this->logger->debug('session not valid');
                        $request = $this->handleToken($uri, $response, $request, $this->loginUrl);
                    }
                    else {
                        $this->logger->debug('session valid');
                        $request = $request->withAttribute('session', $sessionValid);
                    }
                }
                else {
                    $this->logger->debug('api route');
                    $request = $this->handleToken($uri, $response, $request, $this->loginUrl);
                }

            } catch (ExpiredException $expiredException) {

                $this->logger
                    ->error('Exception Caught: ' . $expiredException->getMessage(), $expiredException->getTrace());
                return $this->sendError();
            } catch (Exception $exception) {

                $this->logger
                    ->error('Exception Caught: ' . $exception->getMessage());
                $this->logger
                    ->error($exception->getTraceAsString());
                return $this->sendError();
            }

            return $out ? $out($request, $response) : $response;
        }

        /**
         * @param Request $request
         * @param string $uid
         * @return Request
         */
        private function login(Request $request, $uid)
        {
            $this->logger->debug('attempting login');
            /**
             * @var SessionInterface $session
             */
            $session = $request->getAttribute('session');
            if (!$session->has('uid')) {
                $session->set('uid', $uid);
            }
            $this->logger->debug($session->has('uid'));
            $actor = $this->getActor($request->getAttribute('user')['uid']);
            if ($session) {
                $this->logger->debug('setting session');
                $actor->setSession($session);
            }

            $request = $request->withAttribute('actor', $actor);
            $this->logger->debug('returning from login');
            return $request;
        }

        /**
         * @param $uid
         * @return User|Collection
         */
        private function getActor($uid)
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

        private function verifyKeyAndToken($isApi)
        {
            if (!$this->token && $this->enforce) {
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
                if (time() > $created + $lifetime || !$uid) {
                    return false;
                }
            }
            return $session;
        }

        /**
         * @param string $uid
         * @return SessionInterface
         */
        private function startSession($uid)
        {
            $session = new Session();
            $session->migrate(true, 21600);
            $session->start();

            if (!$session->has('uid')) {
                $session->set('uid', $uid);
            }

            return $session;
        }

        /**
         * @param string $uri
         * @param Response $response
         * @param Request $request
         * @param string $formedUrl
         * @return Request|RedirectResponse|JsonResponse
         */
        private function handleToken($uri, Response $response, Request $request, $formedUrl)
        {
            $this->logger->debug('handling token');
            // Session doesn't exist so check JWT
            $valid = $this->verifyKeyAndToken($this->isApi);

            if ($valid) {
                $jwt = JWT::decode($this->token, $this->key, ['HS256']);
                $request = $request->withAttribute("user", ['jwt' => $this->token, 'uid' => $jwt->uid]);

//                $newSession = $this->startSession($jwt->uid);
//                $request = $request->withAttribute('session', $newSession);

                return $request = $this->login($request, $jwt->uid);
            }
            else {
                $this->logger->debug($formedUrl);
                if (!$this->isApi) {
                    return new RedirectResponse($formedUrl);
                }
                else {
                    return new JsonResponse(['authorized' => false], 401);
                }
            }
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
    }