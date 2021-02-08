<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class cockpit extends \XLtrace\Hades\module {
  var $standalone = TRUE;
  function get($for=NULL, &$set=array()){
    switch(strtolower($for)){
      case 'mailbox': $str = $this->mailbox(); break;
      default:
        return FALSE;
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if($this->standalone === TRUE){
      if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
      if($this->mode == "text/html" && reset($el)!=='html' && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    }
    return $str;
  }
  function mailbox(){
    $note = NULL;
    if(\XLtrace\Hades\authenticated() !== TRUE){ return \XLtrace\Hades\signin(); }
    $s = \XLtrace\Hades\status_json(FALSE);
    if($s['PHPMailer'] === false){ return \XLtrace\Hades\encapsule('Unable to send email.', NULL); }
    $set = array();
    /*settings*/ $set = array_merge(\XLtrace\Hades\file_get_json(\XLtrace\Hades\mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
    $set['message'] = (isset($_POST['message']) ? $_POST['message'] : (isset($_GET['message']) ? $_GET['message'] : NULL));
    $set['title'] = (isset($_POST['title']) ? $_POST['title'] : (isset($_GET['title']) ? $_GET['title'] : NULL));
    // note you should proces $_POST['raw'] for commandline execution
    foreach(array('to','cc','bcc','reply-to','from') as $m){
      $set[$m] = (isset($_POST[$m]) ? array_merge((isset($set[$m]) && is_array($set[$m]) ? $set[$m] : array()), \XLtrace\Hades\emailaddress_str2array($_POST[$m])) : (isset($set[$m]) ? $set[$m] : array() ));
      $set[$m] = \XLtrace\Hades\tag_array_unique('email', $set[$m]);
      $set[$m] = \XLtrace\Hades\emailaddress_autocomplete($set[$m]);
      if(in_array($m, array('reply-to','from'))){ $set[$m] = end($set[$m]); }
      $set[$m.'Str'] = \XLtrace\Hades\emailaddress_array2str($set[$m]);
    }
    //*debug*/ print '<pre>'; print_r($set); print '</pre>';

    /*settings*/ $set = array_merge(\XLtrace\Hades\file_get_json(\XLtrace\Hades\mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
    $note = \XLtrace\Hades\send_mail($set);

    //*debug*/ print '<pre>'; print_r($_POST); print_r($set); print '</pre>';
    $html = self::compose_mail_html(array_merge($set, array('notification'=>$note) ));
    \XLtrace\Hades\encapsule($html, NULL);
    return FALSE;
  }
  public static function compose_mail_html($set=array()){
    return \XLtrace\Hades\morph('{notification|}<form method="POST" class="compose-mail">'
      .'<style>form.compose-mail label span { display: inline-block; min-width: 125px; } form.compose-mail span.fw { display: inline-block; width: 575px; } form.compose-mail textarea, form.compose-mail input[name=title] { width: 450px; height: 40px; min-height: 40px; box-sizing: border-box; margin: 2px; padding: 5px 8px; font-family: arial; font-size: 11pt; } form.compose-mail textarea { padding: 10px 14px; resize: vertical; } form.compose-mail textarea[name=message] { height: 200px; } form.compose-mail input[type=submit], form.compose-mail span.fw input { float: right; }</style>'

      .'<label for="to"><span>To: </span><textarea name="to" id="to" rows="1" cols="20" class="Emailaddress">{toStr|}</textarea></label><br>'
      .'<label for="cc"><span>CC: </span><textarea name="cc" id="cc" rows="1" cols="20" class="Emailaddress">{ccStr|}</textarea></label><br>'
      .'<label for="bcc"><span>BCC: </span><textarea name="bcc" id="bcc" rows="1" cols="20" class="Emailaddress">{bccStr|}</textarea></label><br>'

      .'<label for="title"><span>Title: </span><input type="text" name="title" id="title" value="{title|}" placeholder="Title"></label><br>'
      .'<label for="message"><span>Message: </span><textarea name="message" id="message" rows="8" cols="20" class="wysiwyg html">{message|}</textarea></label><br>'
      .'<span class="fw"><input type="submit" name="action" value="Send"/> <input type="button" name="action" value="Preview"/></span>'
      .'</form>', $set);
  }
}
?>
