<?php
namespace XLtrace\Hades;
if((defined('STATIC_MIRROR_ENABLE') ? STATIC_MIRROR_ENABLE : TRUE) && basename(dirname(__DIR__, 2)) != 'vendor'){
  ini_set('display_errors', 1);
  ini_set('display_startup_errors', 1);
  error_reporting(E_ALL);


  $path = __DIR__.'/cache/';
  $patch = __DIR__.'/patch/';
  if(file_exists(__DIR__.'/settings.php')){ require_once(__DIR__.'/settings.php'); }

  if(file_exists(__DIR__.'/vendor/autoload.php') && !defined('COMPOSER')){ define('COMPOSER', TRUE); require_once(__DIR__.'/vendor/autoload.php'); }
  if(file_exists(__DIR__.'/simple_html_dom.php')){ require_once(__DIR__.'/simple_html_dom.php'); }
  if(file_exists(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php')){ require_once(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php'); }

  if(!defined('STATIC_MIRROR_LIFESPAN')){ define('STATIC_MIRROR_LIFESPAN', 3600); }
  if(!defined('STATIC_MIRROR_SHORT_BASE')){ define('STATIC_MIRROR_SHORT_BASE', 36); }
  if(!defined('STATIC_MIRROR_SHORT_LENGTH')){ define('STATIC_MIRROR_SHORT_LENGTH', 8); }
  if(!defined('STATIC_MIRROR_ALLOW_MAIL')){ define('STATIC_MIRROR_ALLOW_MAIL', FALSE); }
  if(!defined('STATIC_MIRROR_BASE')){ define('STATIC_MIRROR_BASE', __DIR__); }
  if(!defined('HERMES_REMOTE')){ define('HERMES_REMOTE', 'http://fertilizer.wyaerda.nl/hermes/remote.php'); }

  if(class_exists('JSONplus')){ $_POST['raw'] = \JSONplus::worker('raw'); }
}

require_once('hades.php');

//*debug*/ print_r(get_included_files());

if((defined('STATIC_MIRROR_ENABLE') ? STATIC_MIRROR_ENABLE : TRUE) && basename(dirname(__DIR__, 2)) != 'vendor'){
  //phpinfo(32); // $_SERVER['REQUEST_URI'] $_SERVER['SCRIPT_NAME'] $_SERVER['PHP_SELF']
  /*fix*/ if(!isset($_GET['for'])){$_GET['for'] = (isset($_SERVER['PHP_SELF']) ? substr($_SERVER['PHP_SELF'],1) : NULL);}
  $s = $settings = array('standalone'=>FALSE,'path'=>$path,'patch'=>$patch); foreach(\XLtrace\Hades\module_var_list() as $z){ if(!in_array($z, array('root','mapper','path','patch')) && isset($_GET[$z])){ $settings[$z] = $_GET[$z]; } }
  $res = \XLtrace\Hades\get($_GET['for'], $s, array('auth2ndFA','authenticate','status',array('module'=>'sitemap','settings'=>array('standalone'=>TRUE)),array('module'=>'wiki','settings'=>array('root'=>__DIR__,'mode'=>'text/html','standalone'=>$settings['standalone'])),'maintenance','management','static_mirror'), $settings);
  if($res !== TRUE){ print $res; }
}
?>
