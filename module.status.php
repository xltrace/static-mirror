<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class status extends \XLtrace\Hades\module {
  function get($for=NULL, &$set=array()){
    switch(strtolower($for)){
      case 'status': $str = $this->status_html($set, TRUE); break;
      case 'status.json': $str = $this->status_json((!is_array($set) ? $set : (isset($set['print']) ? $set['print'] : NULL))); break;
      default:
        return FALSE;
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if(isset($this->standalone) && $this->standalone === TRUE){
      if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
      //if($this->mode == "text/html" && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    }
    return $str;
  }

  function status(){
    $html = FALSE;
    $s = $this->status_json(FALSE);
    if(isset($s['system-fingerprint'])){ $html = $this->status_html($s, TRUE); }
    else{
      $html = NULL; $header = TRUE;
      foreach($s as $key=>$set){ $html .= $this->status_html($set, $header); $header = FALSE; }
    }
    return $html;
    //\XLtrace\Hades\encapsule($html, TRUE); return FALSE;
  }
  function status_html($set=array(), $with_style=FALSE){
    $str = NULL;
    if($with_style !== FALSE){
      $str .= '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css"/>';
      $str .= '<link ref="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/brands.min.css"/>';
      $str .= '<style>a { text-decoration: none; color: #555; } a:hover { text-decoration: underline; } a:hover i { opacity: 0.8; } .bigicon { font-size: 16pt; margin: 4px 2px; } .green { color: green; } .light-gray { color: #CCC; } .black { color: black; } .gray { color: gray; } .red { color: red; }</style>';
    }

    $icstr = NULL;
    if(is_bool($set)){ return $str; }
    $icons = array('configured'=>'cog','force-https'=>'lock','htaccess'=>'hat-wizard','2ndFA'=>'paper-plane',/*'registery'=>'user-plus',*/'whitelist'=>'clipboard-list','mirror'=>'closed-captioning',/*'active-mirror'=>'microscope',*/'alias'=>'object-ungroup','cache'=>'copy',/*'crontab'=>'stopwatch',*/'encapsule'=>'file-import','simple_html_dom'=>'code','patch-size'=>'dumbbell',/*'hades'=>'fire-alt',*/'composer'=>'database','composer-phar'=>'robot','hermes'=>'comment-dots'/*,'wiki'=>'file-word'*/,'mailbox'=>'envelope-open-text'/*,'cockpit'=>'mail-bulk','backup'=>'file-archive'*/);
    $iconsurl = array('hermes'=>'hermes-remote','configured'=>'{URI|}/configure','backup'=>'{URI|}/backup','cockpit'=>'{URI|}/cockpit','wiki'=>'{URI|}/wiki','mailbox'=>'{URI|}/mailbox','2ndFA'=>'{URI|}/signin','registery'=>'{URI|}/register');
    foreach($icons as $tag=>$ico){
      $href = (isset($iconsurl[$tag]) && (isset($set[$tag]) ? !($set[$tag] === FALSE) : FALSE) );
      if($href){ $icstr .= '<a href="'.(isset($set[$iconsurl[$tag]]) ? $set[$iconsurl[$tag]] : $iconsurl[$tag]).'">'; }
      $icstr .= '<i class="bigicon fa fa-fw fa-'.$ico.' '.$ico.(isset($set[$tag]) && (is_bool($set[$tag]) || $set[$tag] == '0') ? ($set[$tag] == TRUE ? ' true green' : ' false light-gray') : ' null black').'" title="'.$tag.(isset($set[$tag]) && !is_bool($set[$tag]) ? ': '.$set[$tag] : NULL).'"></i>';
      if($href){ $icstr .= '</a>'; }
    }

    $str .= '<p><i class="bigicon fa fa-swatchbook black" title="{system-size} {system-fingerprint|} {system-mod|}"></i> <a href="{URI|#}" style="display: inline-block; min-width: 240px;">{URI|localhost}</a> '.$icstr.' <small style="float: right;" class="light-gray">{SERVER_SOFTWARE|} {SERVER_PROTOCOL|}</small></p>';

    $this->mode = 'text/html';
    return $str;
    //return \XLtrace\Hades\morph($str, $set);
  }
  function status_json($print=NULL){
    $json = FALSE;
    if(isset($_GET['all'])){ $json = \XLtrace\Hades\run_slaves('status.json'); }
    $stat = array('cache-mod-upoch'=>@filemtime(__DIR__.'/cache/index.html'),'system-mod-upoch'=>filemtime(__DIR__.'/static-mirror.php'));
    $stat['cache-mod'] = date('c', $stat['cache-mod-upoch']);
    $stat['system-mod'] = date('c', $stat['system-mod-upoch']);
    $stat['cache-size'] = \XLtrace\Hades\get_size(__DIR__.'/cache/', TRUE);
    $stat['cache'] = ($stat['cache-mod-upoch'] == FALSE ? FALSE : TRUE);
    $stat['patch-size'] = \XLtrace\Hades\get_size(__DIR__.'/patch/', TRUE);
    $stat['size'] = \XLtrace\Hades\get_size(__DIR__.'/', TRUE);
    $stat['system-size'] = filesize(__DIR__.'/static-mirror.php');
    $stat['system-fingerprint'] = md5_file(__DIR__.'/static-mirror.php');
    $stat['htaccess'] = file_exists(__DIR__.'/.htaccess');
    $stat['htaccess-fingerprint'] = md5_file(__DIR__.'/.htaccess');
    $stat['curl'] = (!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec') ? FALSE : TRUE);
    $stat['hermes'] = (file_exists(\XLtrace\Hades\hermes_file()) && $stat['curl']);
    if($stat['hermes'] === TRUE){
      $hermes = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), TRUE, array());
      $stat['hermes-remote'] = preg_replace('#^[\?]#', '', $hermes['url']);
    }
    $stat['configured'] = file_exists(\XLtrace\Hades\static_mirror_file());
    $stat['alias'] = file_exists(\XLtrace\Hades\alias_file());
    if($stat['alias'] === TRUE){
      $alias = \XLtrace\Hades\file_get_json(\XLtrace\Hades\alias_file(), TRUE, array());
      if(isset($alias['#'])){ $stat['alias-domain'] = preg_replace('#^[\?]#', '', $alias['#']); }
      if(isset($alias['*'])){ $stat['alias-domain'] = preg_replace('#^[\?]#', '', $alias['*']); }
      $stat['alias-count'] = count($alias);
      $stat['alias-mod-upoch'] = @filemtime(\XLtrace\Hades\alias_file());
      $stat['alias-mod'] = date('c', $stat['alias-mod-upoch']);
      $stat['alias-fingerprint'] = md5_file(\XLtrace\Hades\alias_file());
    }
    $stat['mirror'] = count(\XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array()));
    $stat['cache-count'] = (count(scandir(__DIR__.'/cache/')) - 2);
    $stat['pages'] = \XLtrace\Hades\count_pages(__DIR__.'/cache/', array('html','htm','txt'));
    $stat['sitemap'] = \XLtrace\Hades\count_pages(__DIR__.'/cache/', array('html','htm','txt'), TRUE);
    $stat['encapsule'] = (\XLtrace\Hades\encapsule(NULL, FALSE) !== NULL);
    $stat['encapsule-size'] = strlen(\XLtrace\Hades\encapsule(NULL, FALSE));
    $stat['addressbook'] = (file_exists(\XLtrace\Hades\addressbook_file()) ? count(\XLtrace\Hades\file_get_json(\XLtrace\Hades\addressbook_file(), TRUE, array())) : FALSE);
    $stat['whitelist'] = (file_exists(\XLtrace\Hades\whitelist_file()) ? count(\XLtrace\Hades\file_get_json(\XLtrace\Hades\whitelist_file(), TRUE, array())) : FALSE);
    $stat['force-https'] = (file_exists(__DIR__.'/.htaccess') ? (preg_match('#RewriteCond \%\{HTTPS\} \!\=on#', file_get_contents(__DIR__.'/.htaccess')) > 0 ? TRUE : FALSE) : FALSE);
    $stat['hades'] = (defined('HADES_MODULES') && TRUE); //future feature: have the hades system integrated into the non-static parts of this mirror, with use of the encapsule skin
    $stat['crontab'] = FALSE; //future feature: have crontab-frequency enabled to run update/upgrade/backup
    $stat['wiki'] = ($stat['hades'] && class_exists('\XLtrace\hades\module\wiki')); //future feature: HADES module WIKI (depends on JSONplus/markdown)
    $stat['slaves'] = (file_exists(\XLtrace\Hades\slaves_file()) ? count(\XLtrace\Hades\file_get_json(\XLtrace\Hades\slaves_file(), TRUE, array())) : 0);
    $stat['2ndFA'] = $stat['mailbox'] = FALSE; /*placeholder*/
    $stat['cockpit'] = FALSE; //future feature: be able to send bulk-email to mailinglist.json based upon encapsule with custom content (requires PHPMailer)
    $stat['registery'] = FALSE; //future feature: allow visitors to leave their email-emailaddress in mailinglist.json
    $stat['active-mirror'] = FALSE; //future feature: enables active mirroring, for example when form-data is being committed. Form-data will be forwarded.
    $stat['backup'] = FALSE; //future feature: allow to backup the settings with the patch into an zip-file
    ksort($stat);
    $stat['URI'] = \XLtrace\Hades\current_URI();
    $stat['composer'] = (file_exists(__DIR__.'/composer.json') && file_exists(__DIR__.'/vendor/autoload.php')); //future feature: upgrade components by composer
    $stat['composer-phar'] = (file_exists(__DIR__.'/composer.phar'));
    $stat['JSONplus'] = (class_exists('JSONplus'));
    if($stat['JSONplus'] === TRUE){
      $stat['markdown'] = (class_exists('\JSONplus\markdown') || class_exists('\Morpheus\markdown'));
      $stat['qtranslate'] = class_exists('\JSONplus\qTranslate');
      $stat['morpheus'] = (class_exists('\JSONplus\morpheus') || class_exists('\Morpheus'));
    }
    $stat['simple_html_dom'] = (file_exists(__DIR__.'/simple_html_dom.php') || class_exists('simple_html_dom_node'));
    $stat['PHPMailer'] = (class_exists('\PHPMailer\PHPMailer\PHPMailer') && STATIC_MIRROR_ALLOW_MAIL !== FALSE);
    $stat['mailbox'] = ($stat['PHPMailer'] && file_exists(\XLtrace\Hades\mailbox_file()));
    $stat['2ndFA'] = ($stat['PHPMailer'] && $stat['mailbox'] && $stat['whitelist'] !== FALSE);
    /*debug*/ if(isset($_GET['system']) && $_GET['system'] == 'true'){ $stat = array_merge($stat, $_SERVER); }
    foreach(explode('|', 'SERVER_SOFTWARE|SERVER_PROTOCOL') as $i=>$s){ if(isset($_SERVER[$s])){ $stat[$s] = $_SERVER[$s]; } } #|HTTP_HOST
    if($json !== FALSE){
      $json[\XLtrace\Hades\current_URI()] = $stat;
    }
    else{
      $json = $stat;
    }
    $this->set = $json;
    $this->mode = 'application/json';
    switch($print){
      case TRUE:
        @header('Content-type: application/json;');
        print \XLtrace\Hades\json_encode($json); exit;
        return FALSE; break;
      case NULL:
        //$this->mode = 'application/json';
        return \XLtrace\Hades\json_encode($json);
        break;
      default:
        return $json;
    }
    return $json;
  }
}
?>
