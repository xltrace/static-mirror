<?php
define('STATIC_MIRROR_ENABLE', FALSE);

if(file_exists(__DIR__.'/settings.php')){ require_once(__DIR__.'/settings.php'); }
if(file_exists(__DIR__.'/vendor/autoload.php')){ define('COMPOSER', TRUE); require_once(__DIR__.'/vendor/autoload.php'); }
if(class_exists('JSONplus')){ $_POST['raw'] = \JSONplus::worker('raw'); }
if(file_exists(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php')){ require_once(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php'); }
require_once(__DIR__.'/static-mirror.php');

/*fix*/ if(!isset($_GET['for'])){$_GET['for'] = (isset($_SERVER['PHP_SELF']) ? substr($_SERVER['PHP_SELF'],1) : NULL);}

$settings = array('root'=>__DIR__);
if(isset($_GET['mode'])){ $settings['mode'] = $_GET['mode']; }
if(isset($_GET['for'])){ $settings['for'] = $_GET['for']; }

$mod = (isset($_GET['module']) ? $_GET['module'] : 'wiki');

if(substr($mod, 0, 1) == '\\'){
  $c = $mod;
}
else{
  if(file_exists(__DIR__.'/module.'.$mod.'.php')){ require_once(__DIR__.'/module.'.$mod.'.php'); }
  $c = '\\XLtrace\\Hades\module\\'.$mod;
  /*fix*/ if(!class_exists($c)){ $c = '\\XLtrace\\Hades\\'.$mod; }
}
if(!class_exists($c)){ print 'Module '.$mod.' is not available.'."\n"; exit; }

$module = new $c($settings);

print $module->get((isset($_GET['for']) ? $_GET['for'] : NULL));

/*debug*/ if(isset($_GET['debug'])){ print_r($module); }
?>
