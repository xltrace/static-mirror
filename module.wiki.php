<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class wiki extends \XLtrace\Hades\module {
  var $standalone = TRUE;
  var $file = array();
  function get($for=NULL, &$set=array()){
    if(!is_dir($this->root)){ return FALSE; }
    $str = FALSE;
    $el = $this->extentions();
    $ext = FALSE; if(preg_match('#\.([a-z0-9]+)$#', $for, $buff)){ $ext = $buff[1]; }
    switch(strtolower($for)){
      case 'toc': $str = $this->toc(); break;
      case 'sitemap.xsl': $str = \XLtrace\Hades\module_get('sitemap','sitemap.xsl'); $this->mode = 'application/xsl'; break;
      case 'sitemap-wiki.xml': case 'sitemap-wiki.json':
        $map = $this->mapper_sitemap_json();
        //if(in_array($ext, array('xml','json','xsl','html')) && $for == substr($this->get_sitemap_URI(TRUE), 0, -3).$ext){
          $str = \XLtrace\Hades\module_get('sitemap','sitemap.'.$ext,$map); $this->mode = 'application/'.$ext;
        //}
        break;
      default:
        /*limited with ext*/ if(preg_match('#\.('.implode('|', $el).')$#', $for, $buffer)){ $el = array($buffer[1]); $for = substr($for, 0, -1*(strlen($buffer[1])+1)); }
        foreach($el as $ext){
          $f = $this->root.$for.'.'.$ext;
          if(file_exists($f)){
            $str = file_get_contents($f); $el = array($ext); $this->file['src'] = $f; $this->file['ext'] = $ext;
          }
        }
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if($this->standalone === TRUE){
      if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
      if($this->mode == "text/html" && reset($el)!=='html' && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    }
    return $str;
  }
  function get_sitemap_URI($short=FALSE){
    $uri = \XLtrace\Hades\current_URI(basename(str_replace('\\','/',get_class($this))).'-sitemap.xml');
    if($short !== FALSE){ $uri = substr(parse_url($uri, PHP_URL_PATH),1); }
    return $uri;
  }
  function mapper_sitemap_json($set=array()){
    $map = array();
    $list = scandir($this->root);
    $el = $this->extentions();
    foreach($list as $i=>$f){
      if(!preg_match('#^[\.]{1,2}$#', $f) && preg_match('#\.('.implode('|',$el).')$#', $f, $buffer)){
        $map[] = array('loc'=>\XLtrace\Hades\current_URI(substr($f,0,-1*(strlen($buffer[1])+1))) );
      }
    }
    return $map;
  }
}
?>
