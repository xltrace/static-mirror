<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
require_once(__DIR__.'/module.authenticate.php');
class auth2ndFA extends \XLtrace\Hades\module\authenticate {
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
  function requestaccess($emailaddress=NULL){
    /*fix*/ if($emailaddress === NULL && isset($_POST['emailaddress'])){ $emailaddress = $_POST['emailaddress']; }
    $s = self::status_json(FALSE);
    if(FALSE && $s['2ndFA'] === FALSE){
      \XLtrace\Hades\encapsule('Request Access is not allowed or able to do an 2<sup>nd</sup>FA method request', NULL);
      return FALSE;
    }
    $mode = NULL;
    $key = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), 'key', FALSE);
    if(isset($emailaddress)){
      $mode = 'request';
      if(\XLtrace\Hades\is_whitelisted($emailaddress)){ # check if emailaddress exists within database
        $data = array('e'=>$emailaddress,'i'=>$_SERVER['REMOTE_ADDR'],'t'=>(int) date('U'));
        $jsonstr = json_encode($data);
        $m = \XLtrace\Hades\encrypt($jsonstr, $key);
        $short = \XLtrace\Hades\put_short_by_m($m);
        $fs = array_merge($data, array('data'=>$data, 'json'=>$jsonstr, 'short'=>$short, 'm'=>$m, 'l'=>strlen($m), 'sURI'=>\XLtrace\Hades\current_URI(array('for'=>$_GET['for'],'m'=>$short)), 'mURI'=>\XLtrace\Hades\current_URI(array('for'=>$_GET['for'],'m'=>$m)), 'URI'=>\XLtrace\Hades\current_URI() ));
        //*debug*/ print '<pre>'; print_r($fs); print '</pre>';
        //*debug*/ print '<pre>'; $raw = str_repeat($data['e'],20); for($i=1;$i<=strlen($raw);$i++){ $j = \XLtrace\Hades\encrypt(substr($raw, 0, $i), $key); print $i.".\t".strlen($j)."\t".number_format($i/strlen($j)*100 , 2)."%\t".$j."\n";} print '</pre>';
        # email by PHPMailer $data['e'] := \XLtrace\Hades\current_URI($m)
        self::send_mail('Request of access by 2ndFA', self::requestaccess_email_html($fs), $emailaddress, $fs);
      } else { //emailaddress is not whitelisted!!
        $mode = 'request-failed';
      }
    } elseif(isset($_GET['m'])){
      $mode = 'receive';
      \XLtrace\Hades\authenticate_by_hash($_GET['m'], $key);
    }
    switch(strtolower($mode)){
      case 'receive':
        //self::process_requestaccess();
        $html = '(receive data, try to authenticate)';
        break;
      case 'request':
        $html = '(request made, a mail has been sent)';
        break;
      case 'request-failed':
        $html = '(request failed)';
        break;
      default:
        $html = '(insert emailaddress form)';
        $html = '<form method="POST"><table><tr><td>Email address:</td><td><input name="emailaddress" type="email"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Request Access" /></td></tr></table></form>';
    }
    \XLtrace\Hades\encapsule($html, NULL);
    return FALSE;
  }
  function requestaccess_email_html($set=array()){
    $html = 'You have requested access to <a href="{URI|localhost}">{URI|localhost}</a>. Your access is being granted by this link: <a href="{sURI|localhost}">{sURI|}</a>';
    return \XLtrace\Hades\morph($html, $set);
  }
}
?>
