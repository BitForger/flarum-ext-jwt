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
    use Illuminate\Database\Eloquent\Collection;
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use Zend\Stratigility\MiddlewareInterface;

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
            $this->key = getenv("API_SECRET");

            $uri = $request->getServerParams()['REQUEST_URI'];
            $this->logger->notice($uri);

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

            if (!$this->token && $this->enforce && $uri !== '/api/token') {
                return $response->withStatus(401)
                    ->withBody($unauthBody)
                    ->withHeader("Content-Type", "application/json");
            }

            if (!$this->key && $this->enforce) {
                return $response->withStatus(500);
            }

            try {
                $jwt = JWT::decode($this->token, $this->key, ['HS256']);
                $request = $request->withAttribute("user", ['jwt' => $this->token, 'uid' => $jwt->uid]);

                $request = $this->login($request);
            } catch (ExpiredException $expiredException) {
                if ($this->enforce && $uri !== '/api/token') {
                    return $response->withStatus(401)
                        ->withBody($unauthBody)
                        ->withHeader("Content-Type", "application/json");
                }

                $this->logger
                    ->error('Exception Caught: ' . $expiredException->getMessage(), $expiredException->getTrace());
            } catch (Exception $exception) {
                if ($this->enforce && $uri !== '/api/token') {
                    return $response->withStatus(500);
                }
                $this->logger
                    ->error('Exception Caught: ' . $exception->getMessage(), $exception->getTrace());
            }

            return $out ? $out($request, $response) : $response;
        }

        /**
         * @param Request $request
         * @return Request
         */
        private function login(Request $request): Request
        {
            $actor = $this->getActor($request->getAttribute('user')['uid']);

            $actor->setSession($request->getAttribute('session'));

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
    }