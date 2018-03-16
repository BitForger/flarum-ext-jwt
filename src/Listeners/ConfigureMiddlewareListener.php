<?php
/**
 * Created by PhpStorm.
 * User: noahkovacs
 * Date: 3/13/18
 * Time: 16:00
 * @soundtrack Last Young Renegade - All Time Low
 */

namespace augustineinstitute\jwt\Listeners;

use function event;
use Exception;
use Firebase\JWT\JWT;
use Flarum\Event\ConfigureMiddleware;
use function getenv;
use Illuminate\Contracts\Events\Dispatcher;
use Monolog\Handler\FirePHPHandler;
use Monolog\Handler\StreamHandler;
use Monolog\Logger;
use function print_r;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;

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
      $this->logger->pushHandler(new StreamHandler(__DIR__ . "/app.log", Logger::DEBUG));
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

    if ($this->applyToAll || ($this->apiOnly && $event->isApi()) || ($this->forumOnly && $event->isForum())) {
      $this->logger->debug("check cookie? " . $this->checkCookies);
      $this->logger->notice(getenv("ENVIRONMENT"));
      $this->logger->alert($_COOKIE[$this->env.'_formed_org-jwt']);
      if ($this->checkCookies) {
        if (isset($_COOKIE[$this->env.'_formed_org-jwt'])) {
          $cookie = $_COOKIE[$this->env.'_formed_org-jwt'];
          $this->logger->alert($cookie);
        }
      }
      $event->pipe(function (Request $request, Response $response, callable $out = null) {
        $header = $request->getHeaderLine("authorization");
        $parts = explode(';', $header);

        if (isset($parts[0]) && starts_with($parts[0], $this->prefix)) {
          /**
           * @var $id string This should be the extracted part to the right of 'Bearer'
           */
          $id = substr($parts[0], strlen($this->prefix));


          if (!$id) {
            return $response->withStatus(401);
          }
          if (!$this->key) {
            return $response->withStatus(500);
          }
          $this->logger->notice($this->key);
          $this->logger->warn($id);
          $jwt = JWT::decode($id, $this->key, ['HS256']);
          $this->logger->notice(print_r($jwt, true));
        }

        return $out ? $out($request, $response) : $response;
      });

    }
  }
}