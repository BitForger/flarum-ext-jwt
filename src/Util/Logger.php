<?php
    /**
     * Created by PhpStorm.
     * User: noahkovacs
     * Date: 4/3/18
     * Time: 08:23
     * @soundtrack Speed of Light (Pt. 2) (feat. Taylor Bennett & Skylr) - Pegboard Nerds
     */

    namespace augustineinstitute\jwt\Util;


    use function array_push;
    use Exception;
    use Monolog\Handler\FirePHPHandler;
    use Monolog\Handler\StreamHandler;

    class Logger extends \Monolog\Logger
    {
        public function __construct($name, $handlers = array(), $processors = array())
        {
            try {
                array_push($handlers, new StreamHandler("storage/logs/jwt_ext.log", Logger::DEBUG));
                array_push($handlers, new FirePHPHandler());
            } catch (Exception $e) {
                \Monolog\Handler\error_log($e);
            }
            parent::__construct($name, $handlers, $processors);
        }
    }