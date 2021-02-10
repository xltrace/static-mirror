<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class management extends \XLtrace\Hades\module {
  var $file = array();
  function get($for=NULL, &$set=array()){
    $str = FALSE;
    switch(strtolower($for)){
      //case 'toc': $str = $this->toc(); break;
      case 'decrypt': $str = $this->decrypt_module(); break;
      default:
    }
    /*cut short*/ if($str === FALSE){ return FALSE; }
    if($this->standalone === TRUE){
      if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
      //if($this->mode == "text/html" && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    }
    return $str;
  }
  function decrypt_module(){
    $error = array();
    $success = \XLtrace\Hades\authenticated();
    if($success !== TRUE){ return \XLtrace\Hades\signin(); }
    $html = "Decrypt Module";
    //edit slaves.json = [ url, url ]
    $result = NULL;
    if(isset($_POST['raw'])){ //duplicate static-mirror.php to $path
      $json = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), TRUE, array());
      $tokens = (isset($_POST['tokens']) && strlen($_POST['tokens'])>0 ? $_POST['tokens'] : $json['key']);
      $result = \XLtrace\Hades\decrypt(trim($_POST['raw']), explode(' ', preg_replace('#\s+#', ' ', $tokens)));
    }
    $debug = (FALSE ? print_r($_POST, TRUE).print_r($error, TRUE).print_r($result, TRUE) : NULL);
    $html = '<pre>'.$debug.'</pre><form method="POST" action="decrypt"><table><tr><th colspan="2">'.$html.'</th></tr><tr><td colspan="2"><textarea name="raw" style="width: 100%; min-width: 400px; min-height: 150px;">'.(isset($_POST['raw']) ? $_POST['raw'] : NULL).'</textarea></td></tr><tr><td>Tokens:</td><td><textarea name="tokens" style="width: 100%;">'.(isset($_POST['tokens']) ? $_POST['tokens'] : NULL).'</textarea></td></tr><tr><td colspan="2"><pre>'.$result.'</pre></td></tr><tr><td><label><input type="checkbox" name="commit" value="true" '.(isset($_POST['commit']) ? 'checked="CHECKED"' : NULL).'/> commit</label></td><td align="right"><input type="submit" value="Decrypt" /></td></tr></table></form>';
    return $html; //self::encapsule($html, TRUE);
    return FALSE;
  }
}
?>
