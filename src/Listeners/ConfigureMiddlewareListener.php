<?php
/**
 * Created by PhpStorm.
 * User: noahkovacs
 * Date: 3/13/18
 * Time: 16:00
 * @soundtrack Last Young Renegade - All Time Low
 */


use Flarum\Event\ConfigureMiddleware;
use Illuminate\Contracts\Events\Dispatcher;

return function (Dispatcher $dispatcher) {
  $dispatcher->listen(ConfigureMiddleware::class, function (ConfigureMiddleware $e) {
    /*if ($e->isForum()) {
      $e->pipe(\Flarum\Http\Middleware\AuthenticateWithJWT::class);
    }*/
    error_log("hello world");
  });
};