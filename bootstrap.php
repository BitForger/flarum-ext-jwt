<?php
/**
 * Created by PhpStorm.
 * User: noahkovacs
 * Date: 3/13/18
 * Time: 15:48
 * @soundtrack California Dreaming - Hollywood Undead
 */

namespace augustineinstitute\jwt;

use augustineinstitute\jwt\Listeners;
use Illuminate\Contracts\Events\Dispatcher;

return function (Dispatcher $events) {
  $listener = new Listeners\ConfigureMiddlewareListener();
  $listener->listen($events);
};