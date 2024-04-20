<?php

require_once "class/Router.php";
require_once "config.php";

ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);

error_reporting(E_ALL);

session_start();

$router = new Router();

$router->run();