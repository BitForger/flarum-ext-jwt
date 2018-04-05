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
    use Firebase\JWT\SignatureInvalidException;
    use Flarum\Core\User;
    use Illuminate\Database\Eloquent\Collection;
    use function print_r;
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Psr\Http\Message\StreamInterface;
    use Symfony\Component\HttpFoundation\Session\SessionInterface;
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
         * AuthenticateWithJWT constructor.
         * @param string|null $token
         * @param bool $enforce
         */
        public function __construct($token, bool $enforce)
        {
            $this->logger = new Logger("flarum_jwt_ext");
            $this->token = $token;
            $this->enforce = $enforce;
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
            $env = getenv('ENVIRONMENT');
            $this->key = getenv("API_SECRET");

            $uri = $request->getServerParams()['REQUEST_URI'];
            $this->logger->notice($uri);

            $proto = $env === "local" ? "http://" : "https://";
            $communityUrlBase = $env === "production" ? 'community.formed.org' : "community." . $env . ".formed.org";
            $communityUrl = $proto . $communityUrlBase . $uri;

            $formedUrlBase = $env === "production" ? 'formed.org/login?url=' . $communityUrl : $env . '.formed.org/login?url=' . $communityUrl;
            $formedUrlBase = $env === "local" ? $env . '.formed.org:3000/login?url=' . $communityUrl : $formedUrlBase;
            $formedUrl = $proto . $formedUrlBase;

            $unauthBody = $response->getBody();
            $unauthBody->write(json_encode(['authenticated' => false]));

            if ($uri === '/api/token') {
                return $out ? $out($request, $response) : $response;
            }

            if (!$this->token) {
                $header = $request->getHeaderLine("authorization");
                $parts = explode(';', $header);

                if (isset($parts[0]) && starts_with($parts[0], $this->prefix)) {
                    $this->token = substr($parts[0], strlen($this->prefix));
                }
            }

            try {
                /**
                 * @var SessionInterface $session
                 */
                $session = $request->getAttribute('session'); // get session
                $sessionValid = $this->checkSession($session); // verify that it is valid, if not then migrate to new one
                $request = $request->withAttribute('session', $sessionValid);

                // Session doesn't exist so check JWT
                $valid = $this->verifyKeyAndToken($uri, $response, $unauthBody);

                if ($valid) {
                    $jwt = JWT::decode($this->token, $this->key, ['HS256']);
                    $request = $request->withAttribute("user", ['jwt' => $this->token, 'uid' => $jwt->uid]);

                    $request = $this->login($request);
                }
                else {

                    $this->logger->debug($formedUrl);
                    return new RedirectResponse($formedUrl);
                }

            } catch (ExpiredException $expiredException) {

                $this->logger
                    ->error('Exception Caught: ' . $expiredException->getMessage(), $expiredException->getTrace());
                if ($this->enforce && $uri !== '/api/token') {
                    return new RedirectResponse($formedUrl);
                }
            } catch (Exception $exception) {

                $this->logger
                    ->error('Exception Caught: ' . $exception->getMessage());
                $this->logger
                    ->error($exception->getTraceAsString());
                if ($this->enforce && $uri !== '/api/token') {
                    return new RedirectResponse($formedUrl);
                }
            }

            return $out ? $out($request, $response) : $response;
        }

        /**
         * @param Request $request
         * @param bool|SessionInterface $validSession
         * @return Request
         */
        private function login(Request $request): Request
        {
            /**
             * @var SessionInterface $session
             */
            $session = $request->getAttribute('session');

            $actor = $this->getActor($request->getAttribute('user')['uid']);
            if ($session) {
                $actor->setSession($session);
            }

            $request = $request->withAttribute('actor', $actor);

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

        private function verifyKeyAndToken(string $uri, Response $response, StreamInterface $unauthBody)
        {
            if (!$this->token && $this->enforce && $uri !== '/api/token') {
                return $response->withStatus(401)
                    ->withBody($unauthBody)
                    ->withHeader("Content-Type", "application/json");
            }

            if (!$this->key && $this->enforce) {
                return $response->withStatus(500);
            }

            return true;
        }

        /**
         * @param SessionInterface $session
         * @param int $attempts
         * @return SessionInterface
         */
        private function checkSession(SessionInterface $session, $attempts = 0)
        {
            if ($session->isStarted()) {
                $metaBag = $session->getMetadataBag();
                $created = $metaBag->getCreated();
                $lifetime = $metaBag->getLifetime();
                $this->logger->debug($created);
                $this->logger->debug($lifetime);
                if (time() > $created + $lifetime && $attempts < 10) {
                    $session->migrate(true, 21600);
                    return $this->checkSession($session, $attempts + 1);
                }
            }
            return $session;
        }
    }