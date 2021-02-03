<?php
define('STATIC_MIRROR_ENABLE', FALSE);

if(file_exists(__DIR__.'/settings.php')){ require_once(__DIR__.'/settings.php'); }
if(file_exists(__DIR__.'/vendor/autoload.php')){ define('COMPOSER', TRUE); require_once(__DIR__.'/vendor/autoload.php'); }
if(file_exists(__DIR__.'/simple_html_dom.php')){ require_once(__DIR__.'/simple_html_dom.php'); }
if(class_exists('JSONplus')){ $_POST['raw'] = \JSONplus::worker('raw'); }
if(file_exists(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php')){ require_once(dirname(__DIR__).'/Morpheus/Morpheus-Markdown.php'); }
require_once(__DIR__.'/static-mirror.php');

$settings = array('mapper'=>str_replace('.php','.json',__FILE__));
if(isset($_GET['mapper'])){ $settings['mapper'] = $_GET['mapper']; }
$module = new \XLtrace\Hades\module($settings);

//print_r($module);
//print_r($module->all_templates());
//var_dump($module->detect($_GET['for']));
//var_dump($module->get($_GET['for']));
print $module->get((isset($_GET['for']) ? $_GET['for'] : NULL));

/*debug*/ if(isset($_GET['debug'])){
  switch($_GET['debug']){
    case 't': case 'templates': print_r($module->all_templates()); break;
    default: print_r($module);
  }
}
?>
