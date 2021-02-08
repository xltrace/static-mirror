<?php
define('STATIC_MIRROR_ENABLE', FALSE);

if(file_exists(__DIR__.'/settings.php')){ require_once(__DIR__.'/settings.php'); }
if(file_exists(__DIR__.'/vendor/autoload.php')){ define('COMPOSER', TRUE); require_once(__DIR__.'/vendor/autoload.php'); }
if(file_exists(__DIR__.'/simple_html_dom.php')){ require_once(__DIR__.'/simple_html_dom.php'); }
if(class_exists('JSONplus')){ $_POST['raw'] = \JSONplus::worker('raw'); }
if(file_exists(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php')){ require_once(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php'); }
require_once(__DIR__.'/static-mirror.php');

/*fix*/ if(!isset($_GET['for'])){$_GET['for'] = (isset($_SERVER['PHP_SELF']) ? substr($_SERVER['PHP_SELF'],1) : NULL);}

$settings = array('mapper'=>str_replace('.php','.json',__FILE__));
foreach(\XLtrace\Hades\module_var_list() as $z){
  if(isset($_GET[$z])){ $settings[$z] = $_GET[$z]; }
}
$set = array();

//print_r($module);
//print_r($module->all_templates());
//var_dump($module->detect($_GET['for']));
//var_dump($module->get($_GET['for']));

$module = new \XLtrace\Hades\module($settings);
print $module->get((isset($_GET['for']) ? $_GET['for'] : NULL), $set);

//print \XLtrace\Hades\get((isset($_GET['for']) ? $_GET['for'] : NULL), $set, $settings);

/*debug*/ if(isset($_GET['debug'])){
  switch($_GET['debug']){
    case 't': case 'templates': print_r($module->all_templates()); break;
    default: print_r($module);
  }
}
?>
