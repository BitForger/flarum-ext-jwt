<?php
/**
 * Created by PhpStorm.
 * User: noahkovacs
 * Date: 3/13/18
 * Time: 16:12
 * @soundtrack Two Hands - We Came As Romans
 */

/*
 * This file is part of Flarum.
 *
 * (c) Toby Zerner <toby.zerner@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace AI\EXT_JWT\Middleware;

use function error_log;
use Flarum\Api\ApiKey;
use Flarum\Core\User;
use Flarum\Http\AccessToken;
use function getenv;
use Psr\Http\Message\ResponseInterface as Response;
use Psr\Http\Message\ServerRequestInterface as Request;
use Zend\Stratigility\MiddlewareInterface;
use Firebase\JWT\JWT;

class AuthenticateWithJWT implements MiddlewareInterface
{
  /**
   * @var string
   */
  protected $prefix = 'Bearer ';

  /**
   * {@inheritdoc}
   */
  public function __invoke(Request $request, Response $response, callable $out = null)
  {
    $headerLine = $request->getHeaderLine('authorization');

    $parts = explode(';', $headerLine);

    if (isset($parts[0]) && starts_with($parts[0], $this->prefix)) {
      /**
       * @var $id {string} This should be the extracted part to the right of 'Bearer'
       */
      $id = substr($parts[0], strlen($this->prefix));
      $key = getenv("API_SECRET");
      $jwt = JWT::decode($id, $key, ['HS256']);
      error_log($jwt);

    }

    return $out ? $out($request, $response) : $response;
  }

}
