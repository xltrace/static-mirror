<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class authenticate extends \XLtrace\Hades\module {
  function get($for=NULL, &$set=array()){
    switch(strtolower($for)){
      case 'signin': $str = $this->signin(); break;
      case 'signoff': $str = $this->signoff(); break;
      case 'profile': $str = $this->profile(); break;
      case 'register': $str = $this->register(); break;
      default:
        return FALSE;
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
    if($this->mode == "text/html" && reset($el)!=='html' && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    return $str;
  }
  function signin(){
    //$s = \XLtrace\Hades\status_json(FALSE);
    //if($s['2ndFA'] === TRUE){ return \XLtrace\Hades\requestaccess(); }
    //else{
      $html = '<form method="POST"><table><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Sign in" /></td></tr></table></form>';
      return $html; //\XLtrace\Hades\encapsule($html, NULL);
    //}
    return FALSE;
  }
  function signoff(){
    \XLtrace\Hades\authenticated();
    unset($_SESSION['token']);
    unset($_SESSION['m']);
    $html = "Static-mirror has forgotton your authentication-token. You are succesfully signed off.";
    return $html; //\XLtrace\Hades\encapsule($html, NULL);
    return FALSE;
  }
  function profile(){ return FALSE; }
  function register(){ return FALSE; }
}
?>
