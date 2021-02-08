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
    switch(strtolower($for)){
      case 'toc': $str = $this->toc(); break;
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
}
?>
