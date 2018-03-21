<?php
    /**
     * Created by PhpStorm.
     * User: noahkovacs
     * Date: 3/13/18
     * Time: 16:00
     * @soundtrack Last Young Renegade - All Time Low
     */

    namespace augustineinstitute\jwt\Listeners;

    use Exception;
    use Firebase\JWT\ExpiredException;
    use Firebase\JWT\JWT;
    use Flarum\Event\ConfigureMiddleware;
    use function getenv;
    use function gettype;
    use Illuminate\Contracts\Events\Dispatcher;
    use function log;
    use Monolog\Handler\FirePHPHandler;
    use Monolog\Handler\StreamHandler;
    use Monolog\Logger;
    use Psr\Http\Message\ResponseInterface as Response;
    use Psr\Http\Message\ServerRequestInterface as Request;
    use function token_name;

    class ConfigureMiddlewareListener
    {
        /**
         * @var Dispatcher $events
         */
        protected $events;
        protected $logger;
        protected $prefix = "Bearer ";


        public function __construct()
        {
            $this->logger = new Logger('flarum-ext-jwt');
            try {
                $this->logger->pushHandler(new StreamHandler("storage/logs/jwt_ext.log", Logger::DEBUG));
                $this->logger->pushHandler(new FirePHPHandler());
            } catch (Exception $e) {
                \Monolog\Handler\error_log($e);
            }
        }

        /**
         * @param Dispatcher $events
         */
        function listen(Dispatcher $events)
        {
            $this->events = $events;
            $events->listen(ConfigureMiddleware::class, [$this, 'handler']);
        }

        /**
         * @var $key string The key to decrypt the token
         */
        private $key;
        /**
         * @var $apiOnly bool
         */
        private $apiOnly;
        private $forumOnly;
        private $applyToAll;
        private $env;
        private $enforce;
        private $checkCookies;
        private $token;
        /**
         * @param ConfigureMiddleware $event
         * @soundtrack In Loving Memory - Alter Bridge
         */
        public function handler(ConfigureMiddleware $event)
        {

            $this->key = getenv("API_SECRET");
            $this->apiOnly = getenv("JWT_API_ONLY") ?: false;
            $this->forumOnly = getenv("JWT_FORUM_ONLY") ?: false;
            $this->applyToAll = !$this->apiOnly && !$this->forumOnly;
            $this->checkCookies = getenv("JWT_CHECK_COOKIE") ?: true;
            $this->env = getenv("ENVIRONMENT") ?: "production";
            $this->enforce = getenv("JWT_ENFORCE") ?: true;

            if (($this->applyToAll || ($this->apiOnly && $event->isApi()) || ($this->forumOnly && $event->isForum()))) {
                if ($this->checkCookies) {
                    if ($this->env !== "production" && isset($_COOKIE[$this->env . '_formed_org-jwt'])) {
                        $this->token = $_COOKIE[$this->env . '_formed_org-jwt'];
                    }
                    else if (isset($_COOKIE['formed_org-jwt'])) {
                        $this->token = $_COOKIE['formed_org-jwt'];
                    }
                    else {
                        $this->token = null;
                    }
                }
                $event->pipe(function (Request $request, Response $response, callable $out = null) {
                    $uri = $request->getServerParams()['REQUEST_URI'];
                    if ($uri === '/api/token') {
                        return $out ? $out($request, $response) : $response;
                    }
                    $this->logger->notice($uri);
                    if (!$this->token) {
                        $header = $request->getHeaderLine("authorization");
                        $parts = explode(';', $header);

                        if (isset($parts[0]) && starts_with($parts[0], $this->prefix)) {
                            $this->token = substr($parts[0], strlen($this->prefix));
                        }
                    }
                    if (!$this->token && $this->enforce && $uri !== '/api/token') {
                        return $response->withStatus(401);
                    }
                    if (!$this->key && $this->enforce) {
                        return $response->withStatus(500);
                    }

                    try {
                        $jwt = JWT::decode($this->token, $this->key, ['HS256']);
                        $request->withAttribute("jwt", $this->token)
                            ->withAttribute("uid", $jwt->uid);
                    }
                    catch (ExpiredException $expiredException) {
                        if ($this->enforce && $uri !== '/api/token'){
                            return $response->withStatus(401);
                        }
                    }
                    catch (Exception $exception) {
                        if ($this->enforce && $uri !== '/api/token'){
                            return $response->withStatus(500);
                        }
                    }

                    return $out ? $out($request, $response) : $response;
                });

            }
        }
    }