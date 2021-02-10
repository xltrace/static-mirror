<?php
namespace XLtrace\Hades;
if((defined('STATIC_MIRROR_ENABLE') ? STATIC_MIRROR_ENABLE : TRUE) && basename(dirname(__DIR__, 2)) != 'vendor'){
  ini_set('display_errors', 1);
  ini_set('display_startup_errors', 1);
  error_reporting(E_ALL);


  $path = __DIR__.'/cache/';
  $patch = __DIR__.'/patch/';
  if(file_exists(__DIR__.'/settings.php')){ require_once(__DIR__.'/settings.php'); }

  if(file_exists(__DIR__.'/vendor/autoload.php')){ define('COMPOSER', TRUE); require_once(__DIR__.'/vendor/autoload.php'); }
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
function get($for=NULL, &$set=array(), $module=FALSE, $settings=array()){
  $bool = $str = $sm = FALSE;
  /*fix*/ $mod = $module; if($mod === FALSE){ $mod = '\\XLtrace\\Hades\\static_mirror'; }
  /*fix*/ elseif(is_string($module) && preg_match('#\|#', $module)){ $mod = explode('|', $module); }
  //*fix*/ if(is_array($module)){ $mod = '\\Xltrace\\Hades\\module'; }

  /*fix*/ if(!is_array($mod)){ $mod = array($mod); }
  foreach($mod as $k=>$mreal){
    if($bool === FALSE){
      if(is_array($mreal)){
        $mcache = $m = (isset($mreal['module']) ? $mreal['module'] : (isset($mreal['m']) ? $mreal['m'] : 'module'));
        $scache = (isset($mreal['settings']) && is_array($mreal['settings']) ? $mreal['settings'] : (isset($mreal['s']) && is_array($mreal['s']) ? $mreal['s'] : $settings));
      }
      else{
        $mcache = $m = $mreal;
        $scache = $settings;
      }
      if(!(substr($m, 0, 1) == '\\')){
        if(file_exists(__DIR__.'/module.'.$m.'.php')){ require_once(__DIR__.'/module.'.$m.'.php'); }
        $m = '\\XLtrace\\Hades\\module\\'.$mcache;
        if(!class_exists($m)){ $m = '\\XLtrace\\Hades\\'.$mcache; }
      }
      if(!class_exists($m) || !method_exists($m, 'get')){ $bool = FALSE; }
      else{
        $sm = new $m($scache);
        $str = $sm->get($for, $set);
        $bool = (!is_bool($str) && is_string($str) ? TRUE : FALSE);
      }
      /*debug*/ if(isset($_GET['debug'])){ print __METHOD__." try module ".$m.' => '.($bool ? 'true' : 'false').' ['.strlen($str)."]\n"; }
    }
  }
  if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
  /*debug*/ if(isset($_GET['debug']) && is_object($sm)){ print_r($sm); }
  if(is_object($sm) && $sm->get_mode() == "text/html" /*&& reset($el)!=='html'*/ && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
  if(is_object($sm) && $sm->get_mode() == "text/html"){ $str = \XLtrace\Hades\encapsule($str); }
  return $str;
}
function module_get($module=FALSE, $for=NULL, &$set=array(), $settings=array()){ return \XLtrace\Hades\get($for, $set, $module, $settings); }
function deprecated($item=NULL){ if(isset($_GET['debug']) && in_array($_GET['debug'], array('true','yes',TRUE))){ print ($item === NULL ? 'A method being used' : $item).' is being deprecated.'."\n"; } }
function notfound($for=NULL){
    $html = "Error 404: Page not found.";
    if($for != NULL){ $html .= "\n\n".$for." is missing."; }
    //return \XLtrace\Hades\encapsule($html, NULL);
    //return FALSE;
    return $html;
}

function static_mirror_file(){ return STATIC_MIRROR_BASE.'/static-mirror.json'; }
function hermes_file(){ return STATIC_MIRROR_BASE.'/hermes.json'; }
function addressbook_file(){ return STATIC_MIRROR_BASE.'/addressbook.json'; }
function alias_file(){ return STATIC_MIRROR_BASE.'/alias.json'; }
function slaves_file(){ return STATIC_MIRROR_BASE.'/slaves.json'; }
function mailbox_file(){ return STATIC_MIRROR_BASE.'/mailbox.json'; }
function whitelist_file(){ return STATIC_MIRROR_BASE.'/whitelist.json'; }
function short_file(){ return STATIC_MIRROR_BASE.'/short.json'; }
function hermes_default_remote(){ return HERMES_REMOTE; }
function raw_git_path(){ return 'https://raw.githubusercontent.com/xltrace/static-mirror/master/'; }
function git_src(){ return 'https://github.com/xltrace/static-mirror'; }

function status_json($print=NULL){ return \XLtrace\Hades\module_get('status','status.json'); }

function authenticated($email=NULL){
    if(!file_exists(\XLtrace\Hades\hermes_file())){ return FALSE; }
    $json = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), TRUE, array());
    @session_start();
    if(isset($_POST['token']) && $_POST['token'] == $json['key']){
        $_SESSION['token'] = $_POST['token'];
        return TRUE;
    }
    if(isset($_GET['m']) && \XLtrace\Hades\authenticate_by_hash($_GET['m'], NULL, $email)){ $_SESSION['m'] = $_GET['m']; return TRUE; }
    if(isset($_SESSION['token']) && $_SESSION['token'] == $json['key']){ return TRUE; }
    elseif(isset($_SESSION['m'])){ return \XLtrace\Hades\authenticate_by_hash($_SESSION['m'], NULL, $email); }
    return FALSE;
}
function authenticate_by_hash($m=NULL, $key=NULL, $email=NULL){
  /*fix*/ if($m === NULL && isset($_SESSION['m'])){ $m = $_SESSION['m']; }
  /*fix*/ if($m === NULL && isset($_POST['m'])){ $m = $_POST['m']; }
  /*fix*/ if($m === NULL && isset($_GET['m'])){ $m = $_GET['m']; }
  /*fix*/ if(isset($m) && preg_match('#\s#', $m)){ $m = str_replace(' ','+',$m); }
  /*short*/ if(strlen($m) == STATIC_MIRROR_SHORT_LENGTH){if($found = \XLtrace\Hades\get_m_by_short($m)){ $m = $found; }}
  /*fix*/ if($key === NULL){ $key = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), 'key', NULL); }
  $jsonstr = \XLtrace\Hades\decrypt($m, $key);
  $data = json_decode($jsonstr, TRUE);
  $lifespan = STATIC_MIRROR_LIFESPAN;
  /*fix*/ if(!isset($_SERVER['REMOTE_ADDR'])){ $_SERVER['REMOTE_ADDR'] = '127.0.0.1'; }
  $ebool = TRUE;
  if($email !== NULL){ $ebool = (isset($data['e']) && $data['e'] == $email); }
  $status = ($ebool && is_array($data) && isset($data['e']) && isset($data['t']) && ($data['t']<=date('U') && $data['t']>=(date('U')-$lifespan)) && isset($data['i']) && $data['i'] == $_SERVER['REMOTE_ADDR'] ? TRUE : FALSE);
  //*debug*/ print '<pre>'; print_r(array('m'=>$m, 'str'=>$jsonstr, 'data'=>$data, 'status'=>$status)); print '</pre>';
  return $status;
}
function generate_m_hash($emailaddress=NULL){
  $m = NULL;
  /*fix*/ if(!isset($_SERVER['REMOTE_ADDR'])){ $_SERVER['REMOTE_ADDR'] = '127.0.0.1'; }
  //*fix*/ if($emailaddress === NULL && isset($_POST['emailaddress'])){ $emailaddress = $_POST['emailaddress']; }
  $key = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), 'key', FALSE);
  //if(\XLtrace\Hades\is_whitelisted($emailaddress)){ # check if emailaddress exists within database
    $data = array('e'=>$emailaddress,'i'=>$_SERVER['REMOTE_ADDR'],'t'=>(int) date('U'));
    $jsonstr = json_encode($data);
    $m = \XLtrace\Hades\encrypt($jsonstr, $key);
    $short = \XLtrace\Hades\put_short_by_m($m);
  //}
  return $m;
}
function get_m_by_short($short){
  $set = \XLtrace\Hades\file_get_json(\XLtrace\Hades\short_file(), TRUE, array());
  if(is_array($set)){foreach($set as $k=>$s){
    /*clean up old listings*/ if($s['t'] < (time() - STATIC_MIRROR_LIFESPAN )){ unset($set[$k]); }
    if($s['short'] == $short){ return $s['m']; }
  }}
  return FALSE;
}
function put_short_by_m($m){
  $short = substr(\XLtrace\Hades\large_base_convert(md5($m), 16, STATIC_MIRROR_SHORT_BASE), 0, STATIC_MIRROR_SHORT_LENGTH);
  $set = \XLtrace\Hades\file_get_json(\XLtrace\Hades\short_file(), TRUE, array());
  /*clean up old listings*/ foreach($set as $k=>$s){ if(isset($s['t']) && $s['t'] < (time() - STATIC_MIRROR_LIFESPAN )){ unset($set[$k]); } }
  $set[] = array('t'=>time(),'short'=>$short,'m'=>$m);
  /*fix*/ $ns = array(); foreach($set as $k=>$s){ $ns[] = $s; } $set = $ns;
  \XLtrace\Hades\file_put_json(\XLtrace\Hades\short_file(), $set);
  return $short;
}
function get_user_emailaddress(){ return \XLtrace\Hades\get_element_from_2ndfa('e'); }
function get_element_from_2ndfa($el='e', $m=NULL, $key=NULL){
  /*fix*/ if($m === NULL && isset($_SESSION['m'])){ $m = $_SESSION['m']; }
  /*fix*/ if($m === NULL && isset($_POST['m'])){ $m = $_POST['m']; }
  /*fix*/ if($m === NULL && isset($_GET['m'])){ $m = $_GET['m']; }
  /*fix: needs @session_start() */ \XLtrace\Hades\authenticated();
  if($m === NULL || strlen($m) < 1){ return FALSE; }
  /*fix*/ if(isset($m) && preg_match('#\s#', $m)){ $m = str_replace(' ','+',$m); }
  /*short*/ if(strlen($m) == STATIC_MIRROR_SHORT_LENGTH){if($found = \XLtrace\Hades\get_m_by_short($m)){ $m = $found; }}
  /*fix*/ if($key === NULL){ $key = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), 'key', NULL); }
  $jsonstr = \XLtrace\Hades\decrypt($m, $key);
  $data = json_decode($jsonstr, TRUE);
  switch(strtolower($el)){
    case 'i': case 'ip': return $data['i']; break;
    case 'iso8901': return date('c', $data['t']); break;
    case 't': case 'timestamp': return $data['t']; break;
    case 'e': case 'email': case 'emailaddress': return $data['e']; break;
    default:
      //future feature: grab additional info from addressbook (filter by emailaddress from 2ndFA)
  }
  return FALSE;
}
function is_whitelisted($email=NULL){
  if(!file_exists(\XLtrace\Hades\whitelist_file())){ return FALSE; }
  $json = \XLtrace\Hades\file_get_json(\XLtrace\Hades\whitelist_file(), TRUE, array());
  return (in_array($email, $json) ? TRUE : FALSE);
}
function signin(){ return \XLtrace\Hades\module_get('authenticate', 'signin'); }
function signoff(){ return \XLtrace\Hades\module_get('authenticate', 'signoff'); }
function file_get_json($file, $as_array=TRUE, $def=FALSE){
  /*fix*/ if(preg_match("#[\n]#", $file)){ $file = explode("\n", $file); }
  if(is_array($file)){
    $set = FALSE;
    foreach($file as $i=>$f){
      $buffer = \XLtrace\Hades\file_get_json($f, $as_array, $def);
      if($buffer !== $def && ($as_array === TRUE ? is_array($buffer) : TRUE)){
        $set = array_merge(($as_array !== TRUE ? array($buffer) : $buffer), (!is_array($set) ? array() : $set));
      }
    }
    return $set;
  }
  $puf = parse_url($file);
  if((is_array($puf) && !isset($puf['schema']) && !isset($puf['host']) ? file_exists($file) : $puf !== FALSE )){
    $raw = file_get_contents($file);
    $json = json_decode($raw, (is_bool($as_array) ? $as_array : TRUE));
    if(!is_bool($as_array)){
      if(isset($json[$as_array])){ return $json[$as_array]; }
      else{ return $def; }
    }
    else{
      return $json;
    }
  }
  return $def;
}
function file_put_json($file, $set=array()){
  if(class_exists('JSONplus')){
    $jsonstr = \JSONplus::encode($set);
  }
  else{
    $jsonstr = json_encode($set);
  }
  return file_put_contents($file, $jsonstr);
}
function build_url($ar=array()){
    // $ar is assumed to be a valid result of parse_url()
    $url = NULL;
    $url .= (isset($ar['scheme']) ? $ar['scheme'].'://' : NULL);
    if(isset($ar['user'])){ $url .= $ar['user'].(isset($ar['pass']) ? ':'.$ar['pass'] : NULL).'@'; }
    $url .= $ar['host'].(isset($ar['port']) ? ':'.$ar['port'] : NULL);
    $url .= ((isset($ar['query']) || isset($ar['fragment']) || isset($ar['path'])) ? (isset($ar['path']) ? (substr($ar['path'], 0, 1) != '/' ? '/' : NULL) : '/') : NULL);
    $url .= (isset($ar['path']) ? $ar['path'] : NULL);
    $url .= (isset($ar['query']) ? '?'.(is_array($ar['query']) ? http_build_query($ar['query']) : $ar['query']) : NULL);
    $url .= (isset($ar['fragment']) ? '#'.$ar['fragment'] : NULL);
    return $url;
}
function url_is_valid_status_json($url){
    if(parse_url($url) == FALSE || strlen($url) < 5){ return FALSE; }
    /*fix*/ if(substr($url, -1) == '/'){ $url = $url.'status.json'; }
    $raw = file_get_contents($url);
    if(strlen($raw) < 4){ return FALSE; }
    $json = json_decode($raw, TRUE);
    if(isset($json['system-fingerprint']) && strlen($json['system-fingerprint']) == 32){ return TRUE; }
    return FALSE;
}
function current_URI($el=NULL, $pl=NULL, $set=array()){
  $uri = array(
    'scheme'=>((
      (isset($_SERVER['REQUEST_SCHEME']) && $_SERVER['REQUEST_SCHEME']=='https') ||
      (isset($_SERVER['SERVER_PORT']) && (string) $_SERVER['SERVER_PORT'] == '443') ||
      (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS']=='on') ||
      (isset($_SERVER['SCRIPT_URI']) && substr($_SERVER['SCRIPT_URI'],0,5)=='https')
    ) ? 'https' : 'http'),
    'host'=>(isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : 'localhost'));
  if($el !== NULL){
    if(is_array($el)){ $uri['query'] = $el; if($pl !== NULL){ $uri['path'] = $pl; } }
    else{ $uri['path'] = $el; if(is_array($pl)){ $uri['query'] = $pl; } }
  }
  /*fix*/ if(is_array($set)){ $uri = array_merge($uri, $set); }
  /*fix*/ if(isset($uri['query']['for']) && (!isset($uri['path']) || strlen($uri['path']) < 1)){ $uri['path'] = $uri['query']['for']; unset($uri['query']['for']); }
  /*fix*/ if(FALSE){foreach(array('module','mapper') as $k){if(isset($_GET[$k]) && !isset($uri['query'][$k])){ $uri['query'][$k] = $_GET[$k]; }}}
  return \XLtrace\Hades\build_url($uri);
}
function url_patch($str, $find=NULL, $host=FALSE){
  if(is_bool($find)){ if($find === FALSE){ return $str; } else { $find = NULL; }}
  /*fix*/ $alt = $find;
  if($host === FALSE){ $host = $_SERVER['HTTP_HOST']; }
  if($find === NULL){
    $find = array('https://localhost/', 'http://localhost/');
    /*future upgrade: grab from patch/.preg*/
  }
  /*fix*/ if(is_string($find)){ $find = array($find); }
  if(is_array($find)){foreach($find as $i=>$el){
    $alt[$i] = (parse_url($el) !== FALSE ? \XLtrace\Hades\current_URI(NULL, NULL, array_merge(parse_url($el), array('host'=>$host))) : $el);
  }}
  /* \/ fix*/
  if(is_array($find)){$ef=array();foreach($find as $i=>$el){ if(preg_match('#[/]#', $el)){ $ef[$i] = str_replace('/','\\/', $el); } $find = array_merge($find, $ef); }}
  if(is_array($alt)){$af=array();foreach($alt as $i=>$el){ if(preg_match('#[/]#', $el)){ $af[$i] = str_replace('/','\\/', $el); } $alt = array_merge($alt, $af); }}

  $str = str_replace($find, $alt, $str);
  return $str;
}
function is_emailaddress($email=NULL){ return filter_var($email, FILTER_VALIDATE_EMAIL); }
function array_urlencode($ar=array(), $sub=FALSE, $implode=TRUE){
  $set = array();
  foreach($ar as $k=>$value){
    $key = (is_bool($sub) ? $k : $sub.'['.$k.']');
    if(is_array($value)){
      $set = array_merge($set, \XLtrace\Hades\array_urlencode($value, $key, FALSE));
    }
    else{
      $set[$key] = $key.'='.urlencode($value);
    }
  }
  return ($implode === TRUE ? implode('&', $set) : $set);
}
function tag_array_unique($tag="email", $to=array(), $merge=array()){
    $set = array_merge($to, $merge);
    $list = array();
    foreach($set as $i=>$a){
      if(isset($a[$tag])){
        if(in_array($a[$tag], $list)){
          $j = array_search($a[$tag], $list);
          $set[$j] = array_merge($set[$j], $set[$i]);
          unset($set[$i]);
        }
        $list[$i] = $a[$tag];
      }
    }
    return $set;
}
function array_filter($set=array(), $match=array(), $limit=array(), &$rid=NULL){
  $delimiter = array('('=>')','{'=>'}','['=>']','<'=>'>'); foreach(array('#','/','@','+','%') as $x){ $delimiter[$x] = $x; }
  $filter = array();
  foreach($set as $k=>$s){
      foreach($match as $x=>$y){
        if($y == NULL || preg_match('#^(true|false|null)$#i', $y)){
          switch(strtolower($y)){
            case 'true':
              if(!isset($s[$x])){ unset($set[$k]); }
              elseif(is_bool($s[$x]) && $s[$x] !== TRUE){ unset($set[$k]); }
              break;
            case 'false':
              if(isset($s[$x]) && $s[$x] !== FALSE){ unset($set[$k]); }
              break;
            default: //case NULL
              if(isset($s[$x]) && !($s[$x] == NULL)){ unset($set[$k]); }
          }
        }
        elseif(isset($s[$x])){
          if(!in_array($x, $filter)){$filter[] = $x;}
          switch(substr($y, 0, 1)){
            case '#': case '/': case '@': case '+': case '$': case '{': case '(': case '[': case '<':
              if(preg_match('@\\'.$delimiter[substr($y, 0, 1)].'(i)?$@', $y)){
                if(!preg_match($y, $s[$x])){
                  unset($set[$k]);
                }
                break; //if not matched, uses default test
              }
            default:
              if($s[$x] != $y){
                unset($set[$k]);
              }
          }
        }
        else{ //remove when $x is not set in $s
          if(in_array($x, $filter)){ unset($set[$k]); }
        }
      }
  }
  if(is_int($limit)){
    $rdb = array_keys($set);
    if($limit == 0){
      $rid = (is_array($rdb) && count($rdb) > 0 ? reset($rdb) : NULL);
      return reset($set);
    }
    reset($set);
    if(isset($rdb[$limit])){$rid = $rdb[$limit];}
    for($i=0;$i<=$limit;$i++){ next($set); }
    return current($set);
  }
  return $set;
}
function json_encode($value, $options=0, $depth=512){
  return (class_exists('JSONplus') ? \JSONplus::encode($value, $options, $depth) : json_encode($value, $options, $depth));
}
function library(){
  return "0123456789" #10
  ."abcdefghij" #20
  ."klmnopqrst" #30
  ."uvwxyzABCD" #40
  ."EFGHIJKLMN" #50
  ."OPQRSTUVWX" #60
  ."YZ-_+!@$%~" #70 (trustworthy up to base62 (10+26+26), backwards-compatible to base70 (pre Xnode v2.0 RC047) )
  ."\"#&'()*,./" #80
  .":;<=>?[\\]^" #90
  ."`{|}" #95
  ."¡¢" #97
  ."£¤¥§©«¬®°±" #107
  ."µ¶»¼½¾¿ÆÐ×" #117
  ."Þßæçð÷ø \t\n"; #127
}
function large_base_convert($numstring, $frombase, $tobase, $bitlength=0, $minlength=0) {
  //*error*/ if($frombase <= 1 || $tobase <= 1){ return $numstring; }
  /*fix*/ if(is_string($frombase)){ $frombase = (int) \XLtrace\Hades\large_base_convert($frombase, 70, 10); }
  /*fix*/ if(is_string($tobase)){ $tobase = (int) \XLtrace\Hades\large_base_convert($tobase, 70, 10); }
  //*debug*/ if($frombase == 1 || $tobase == 1) print '<!-- LBC: '.print_r(array($numstring, $frombase, $tobase, $bitlength, $minlength), TRUE).' -->';
  /*standard behaviour*/ if(is_int($numstring) && $numstring < 256 && $frombase <= 36 && $tobase <= 36 && !($frombase == $tobase)){ $result = base_convert($numstring, $frombase, $tobase); if($minlength !== 0 && strlen($result) < $minlength){ $result = str_repeat('0', $minlength-strlen($result)).$result; } return $result; }
  if($bitlength===0){ $bitlength = strlen(\XLtrace\Hades\large_base_convert(\XLtrace\Hades\large_base_convert($frombase-1, 10, $frombase, -1), $frombase, $tobase, -1)); }
  //$numstring .= ''; /*forced string fix*/
  $numstring = (string) $numstring;
  $chars = \XLtrace\Hades\library();
  $tostring = substr($chars, 0, $tobase);
  $original = $numstring;
  /*CaseClass-fix*/ if($frombase<=36){$numstring = strtolower($numstring);}

  $length = strlen($numstring);
  $result = '';
  for ($i = 0; $i < $length; $i++) {
    $number[$i] = strpos($chars, $numstring{$i});
  }
  do {
    $divide = 0;
    $newlen = 0;
    for ($i = 0; $i < $length; $i++) {
      $divide = $divide * $frombase + $number[$i];
      if ($divide >= $tobase) {
        $number[$newlen++] = (int)($divide / $tobase);
        $divide = $divide % $tobase;
      } elseif ($newlen > 0) {
        $number[$newlen++] = 0;
      }
    }
    $length = $newlen;
    $result = $tostring{$divide} . $result;
  }
  while ($newlen != 0);
  /*CaseClass-fix*/ if($frombase<=36 && $numstring!=$original){$result = strtoupper($result);}
  /*fulllength compatibility-fix*/ if($bitlength > 0 && $bitlength >= strlen((string) $result) ){ $result = str_repeat($chars{1}, $bitlength-strlen((string) $result)).((string) $result); }
  if($minlength !== 0 && strlen($result) < $minlength){ $result = str_repeat('0', $minlength-strlen($result)).$result; }
  return (string) $result;
}
function encrypt($str, $key=FALSE){
  //*move to object*/ if(isset($this) && is_bool($key)){ $key = $this->secret; } elseif($key == NULL || is_bool($key)){ return $str; }
  $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
  $iv = openssl_random_pseudo_bytes($ivlen);
  $ciphertext_raw = openssl_encrypt($str, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
  $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
  $ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
  return $ciphertext;
}
function decrypt($ciphertext, $key=FALSE){
  //*move to object*/ if(isset($this) && is_bool($key)){ $key = $this->secret; }
  if(is_array($key)){
    $awnser = FALSE;
    foreach($key as $i=>$k){
      //$b = (isset($this) ? $this->decrypt($ciphertext, $k) : \XLtrace\Hades\decrypt($ciphertext, $k) );
      $b = \XLtrace\Hades\decrypt($ciphertext, $k);
      if($b !== FALSE){
        $awnser = $b;
        //if(isset($this)){
        //  $this->last = $k;
        //  $this->hit = array_unique(array_merge($this->hit, array($k)));
        //}
        if(defined('JSONplus_KEY_LAST') && defined('JSONplus_KEY_HIT')) {
          global ${JSONplus_KEY_LAST}, ${JSONplus_KEY_HIT};
          ${JSONplus_KEY_LAST} = $k;
          ${JSONplus_KEY_HIT} = array_unique(array_merge((is_array(${JSONplus_KEY_HIT}) ? ${JSONplus_KEY_HIT} : array()), array($k)));
        }
        return $awnser;
      }
    }
    return $awnser;
  }
  //*debug*/ print_r(array('ciphertext'=>$ciphertext, 'key'=>$key));
  //$cipher, $key
  $c = base64_decode($ciphertext);
  $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
  $iv = substr($c, 0, $ivlen);
  if(strlen($iv) < $ivlen){ return FALSE; }
  $hmac = substr($c, $ivlen, $sha2len=32);
  $ciphertext_raw = substr($c, $ivlen+$sha2len);
  $original_plaintext = openssl_decrypt($ciphertext_raw, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
  $calcmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
  if(FALSE && $ciphertext_raw){ print '<pre>'.str_replace(array('<','>'), array('&lt;','&gt;'), print_r(array(
    'ciphertext'=>$ciphertext,
    'c'=>$c,
    'key'=>$key,
    'cipher'=>$cipher,
    'ivlen'=>$ivlen,
    'iv'=>$iv,
    'hmac'=>$hmac,
    'sha2len'=>$sha2len,
    'ciphertext_raw'=>$ciphertext_raw,
    'options'=>$options,
    'original_plaintext'=>$original_plaintext,
    'calcmac'=>$calcmac
  ), TRUE)).'</pre>'; }
  if (hash_equals($hmac, $calcmac)){//PHP 5.6+ timing attack safe comparison
    return $original_plaintext."\n";
  }
  return FALSE;
}
function hermes($path=FALSE, $mode=FALSE, $addpostget=TRUE){
  if(!file_exists(\XLtrace\Hades\hermes_file())){ return FALSE; }
  if(!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec')){ $mode = NULL; }
  # $path + $url + $key
  $set = \XLtrace\Hades\file_get_json(\XLtrace\Hades\hermes_file(), TRUE, array());
  $url = (isset($set['url']) ? $set['url'] : \XLtrace\Hades\hermes_default_remote());
  $key = (isset($set['key']) ? $set['key'] : FALSE);
  $message = array(
    "when"=>date('c'),
    "stamp"=>date('U'),
    "identity"=>substr(md5((isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'localhost')), 0, 24),
    "HTTP_HOST"=>\XLtrace\Hades\current_URI(),
    "load"=>$path,
    "HTTP_USER_AGENT"=>(isset($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : 'cli'),
    "REMOTE_ADDR"=>(isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'localhost')
  );
  if(isset($_SERVER['HTTP_ACCEPT_LANGUAGE'])){ $message["HTTP_ACCEPT_LANGUAGE"] = $_SERVER['HTTP_ACCEPT_LANGUAGE']; }
  //$message['item'] = $message['load'];
  if($addpostget !== FALSE){
    $G = $_GET; $P = $_POST; /*fix*/ if(isset($G['for'])){ unset($G['for']); } if(isset($P['raw']) && strlen($P['raw']) == 0){ unset($P['raw']); }
    if(isset($G) && is_array($G) && count($G) > 0){ $message['_GET'] = $G; }
    if(isset($P) && is_array($P) && count($P) > 0){ $message['_POST'] = $P; }
  }
  $message = json_encode($message);
  if($key !== FALSE){ $message = \XLtrace\Hades\encrypt($message, $key); }
  //*debug*/ print '<!-- HERMES: '.$message.' -->';
  /*fix if curl not exists*/ if($mode === NULL){ return $message; }
  $fm = 'json='.$message; //&var=
  $ch = curl_init( $url );
  curl_setopt( $ch, CURLOPT_POST, 1);
  curl_setopt( $ch, CURLOPT_POSTFIELDS, $fm);
  curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 1);
  curl_setopt( $ch, CURLOPT_HEADER, 0);
  curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1);
  $response = curl_exec( $ch );
  return ($mode === FALSE ? $response : $message);
}
function run_slaves($action=NULL, $list=array()){ //herhaps the naming is politically incorrect; should be changed!
  if(!is_array($list) || count($list) == 0){
    if(!file_exists(\XLtrace\Hades\slaves_file())){ return FALSE; }
    $list = \XLtrace\Hades\file_get_json(\XLtrace\Hades\slaves_file(), TRUE, array());
  }
  $bool = TRUE; $json = array();
  foreach($list as $i=>$url){
    $pu = parse_url($url);
    if($pu !== FALSE && is_array($pu)){
      switch(strtolower($action)){
        case 'upgrade': case 'update':
          $pu['path'] = $pu['path'].(substr($pu['path'], -1) == '/' ? NULL : '/').strtolower($action);
          $buffer = file_get_contents(\XLtrace\Hades\build_url($pu));
          break;
        case 'status': case 'status.json':
          $pu['path'] = $pu['path'].(substr($pu['path'], -1) == '/' ? NULL : '/').'status.json';
          $json[$url] = \XLtrace\Hades\file_get_json(\XLtrace\Hades\build_url($pu));
          break;
        default:
          $bool = FALSE;
      }
    }
  }
  return (count($json) == 0 ? $bool : $json);
}
function get_size($path=STATIC_MIRROR_BASE, $recursive=FALSE){
    $size = 0;
    $list = scandir($path);
    foreach($list as $i=>$f){
      if(!preg_match('#^[\.]{1,2}$#', $f)){
        if(is_dir($path.$f)){
          if($recursive !== FALSE){ $size += \XLtrace\Hades\get_size($path.$f.'/', $recursive); }
        }
        else {
          $size += filesize($path.$f);
        }
      }
    }
    return $size;
}
function count_pages($path=FALSE, $ext=FALSE, $sitemap=FALSE){
    if($path === FALSE){ $path = __DIR__.'/cache/';}
    $c = 0; $s = array();
    $list = scandir($path);
    foreach($list as $i=>$f){
      if(!preg_match('#^[\.]{1,2}$#', $f)){
        if(!is_array($ext)){ $c++; $s[] = $f; }
        elseif(preg_match('#[\.]('.implode('|',$ext).')$#', $f)){ $c++; $s[] = $f; }
      }
    }
    return ($sitemap === FALSE ? $c : $s);
}
function encapsule($content=NULL, $el=FALSE, $template='empty.html'){
  if($el === FALSE){ $el = 'content'; }
  //encapsule when an cache/empty.html skin is available

  // $content = ''.$content.'';
  /*print instruction*/ if(is_bool($el) && $el === TRUE){ print $content; exit; } elseif($el === NULL){ print $content; }
  return $content;
}
function morph($str=NULL, $set=array()){
  if(class_exists('\JSONplus\Morpeus')){ return \JSONplus\Morpheus::parse($str, $set); }
  elseif(class_exists('\Morpeus')){ return \Morpheus::parse($str, $set); }
  preg_match_all('#[\{]([^\}\?\|]+)([^\}]+)?[\}]#', $str, $buffer);
  foreach($buffer[0] as $i=>$hit){
    $with = (isset($set[$buffer[1][$i]]) ? $set[$buffer[1][$i]] : FALSE);
    switch(substr($buffer[2][$i], 0, 1)){
      case '|':
        if($with === FALSE){ $with = substr($buffer[2][$i], 1); }
        break;
      case '?':
        $x = explode(':', $buffer[2][$i]);
        $with = ($with === FALSE ? (isset($x[1]) ? $x[1] : NULL) : substr($x[0], 1));
        break;
      default:
        if($with === FALSE){ $with = $hit; }
    }
    $str = str_replace($hit, $with, $str);
  }
  return $str;
}
function morph_template($template=NULL, $set=array(), $config=array()){
  $extentions = array('m','md','html');
  foreach($extentions as $ext){
  $t = (isset($config['root']) ? $config['root'] : NULL).$template.'.'.$ext;
  //*debug*/ print '<pre>'; print_r(array('template'=>$template,'set'=>$set,'config'=>$config,'t'=>$t,'t_exists'=>file_exists($t))); print '</pre>';
  if(file_exists($t)){
    $raw = file_get_contents($t);
    $raw = \XLtrace\Hades\morph($raw, $set);
    //*markdown fix*/ $raw = \Morpheus\Markdown_decode($raw, array_merge($set, $config)); //$morph = new \Morpheus\markdown(); $raw = $morph->decode($raw, array_merge($set, $config)); //print_r($morph);
    //*debug*/ print_r($raw); exit;
    return $raw;
  }}
  return (file_exists((isset($config['root']) ? $config['root'] : NULL).'template_is_not_found.html') ? \XLtrace\Hades\morph_template('template_is_not_found', $set, $config) : FALSE);
}
function apply_patch($raw=NULL){
  if(isset($this)){
    $path = $this->path;
    $patch = $this->patch;
  }
  else {
    global $path, $patch;
  }
  $list = scandir($patch);
  foreach($list as $i=>$f){
    //*debug*/ print $f."\n";
    if(preg_match('#\.before$#', $f)){
      $before = trim(file_get_contents($patch.$f));
      $after = trim(file_get_contents($patch.substr($f, 0, -7).'.after'));
      $raw = str_replace($before, $after, $raw);
    }
    elseif(preg_match('#\.preg$#', $f)){
      $srp = file_get_contents($patch.$f);
      $pregjson = json_decode($srp, TRUE);
      //*debug*/ print_r($srp); print_r($pregjson);
      foreach($pregjson as $i=>$s){
        if(isset($s['find']) && class_exists('simple_html_dom_node')){
          $html = str_get_html($raw);
          $hit = $html->find($s['find']);
          foreach($hit as $item){
            //print_r($item->plaintext); exit;
            //print "\t".$item->innertext."\n";
            //$item->innertext = NULL;
            if(isset($s['after'])){ $item->innertext = $s['after']; }
            elseif(isset($s['src'])){ $item->innertext = (file_exists($patch.$s['src']) ? file_get_contents($patch.$s['src']) : (file_exists($path.$s['src']) ? file_get_contents($path.$s['src']) : file_get_contents($s['src']) ) );  }
            else{ $item->remove(); }
          }
          $raw = (string) $html;
        }
        if(isset($s['before']) && isset($s['after'])){
          //$raw = preg_replace('#'.$s['before'].'#'.(isset($s['case']) ? 'i' : NULL), $s['after'], $raw);
          $raw = str_replace($s['before'], $s['after'], $raw);
          /*\/ fix*/ if(preg_match('#[/]#', $s['before'])){ $raw = str_replace(str_replace('/','\\/',$s['before']), str_replace('/','\\/',$s['after']), $raw); }
        }
      }
    }
  }
  return $raw;
}
function emailaddress_array2str($to=array()){
    $str = NULL; $i = 0;
    if(is_array($to)){foreach($to as $k=>$t){
      if($i !== 0){ $str .= ', ';}
      if(is_array($t) && isset($t['email'])){
        $str .= (isset($t['name']) ? '"'.$t['name'].'" <'.$t['email'].'>' : $t['email']);
      }
      else{ $str .= $t; }
      $i++;
    }}
    return $str;
}
function emailaddress_str2array($str=NULL){
    $emailpattern = '[_a-zA-Z0-9-]+(\.[_a-zA-Z0-9-]+)*@[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*(\.[a-zA-Z]{2,})';
    $to = $set = array();
    preg_match_all('#'.$emailpattern.'#', $str, $set);
    foreach($set[0] as $i=>$e){
      $to[$i] = array('email' => $e); $str = str_replace($e, '@{'.$i.'}', $str);
    }
    preg_match_all('#(\"([^\"]+)\"\s*\<\@\{([0-9]+)\}\>)#', $str, $set);
    foreach($set[3] as $j=>$m){
      $to[(int) $m]['name'] = $set[2][$j];
    }
    return $to;
}
function emailaddress_autocomplete($to=array(), $set=TRUE, $tag="email"){
    $set = ($set === TRUE ? \XLtrace\Hades\file_get_json(\XLtrace\Hades\addressbook_file(), TRUE, array()) : (is_array($set) ? $set : array()) );
    foreach($to as $i=>$t){
      if(is_string($t)){ $to[$i] = \XLtrace\Hades\array_filter($set, array($tag=>$t), 0); }
      elseif(is_array($t) && isset($t[$tag])){ $m = \XLtrace\Hades\array_filter($set, array($tag=>$t[$tag]), 0); $to[$i] = array_merge($t, (is_array($m) ? $m : array())); }
    }
    return $to;
}

function send_mail($title=NULL, $message=NULL, $to=FALSE, $set=array()){
  if(defined('HADES_ALLOW_MAIL') && HADES_ALLOW_MAIL === FALSE){ return FALSE; } //deadswitch to disable mail
  $count = 0;
  /*fix*/ if(is_bool($set)){ $set = array('preview'=>$set); }
  /*fix*/ if(is_array($title)){ $set = array_merge($set, $title); $title = (isset($set['title']) ? $set['title'] : NULL); $message = (isset($set['message']) ? $set['message'] : $message); if($to === FALSE && isset($set['to'])){ $to = $set['to']; } }
  $set = array_merge(\XLtrace\Hades\file_get_json(\XLtrace\Hades\mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
  //if(\XLtrace\Hades\authenticated() !== TRUE){ return FALSE/*\XLtrace\Hades\signin()*/; }
  if(is_string($message) && preg_match('#[\.](html|md)$#', $message, $ext)){
    $message = (file_exists($message) ? file_get_contents($message) : NULL); //grab $message
    switch($ext[1]){
      case 'md':
        $message = ($message); //parse markdown
        break;
      //case 'html': default: //do nothing to change input
    }
  }
  /* json / single or non addressy fix */ if(!is_array($to)){ if(is_string($to)){ $to = (preg_match('#^\s*[\[\{]#', $to) && preg_match('#[\]\}]\s*$#', $to) ? json_decode($to, TRUE) : \XLtrace\Hades\emailaddress_str2array($to)); } else{ $to = array(); } }
  /*fix*/ if(isset($set['to'])){ $to = array_merge($to, $set['to']); }
  foreach($to as $i=>$t){
    if(is_string($t)){ $t = array('email'=>trim($t)); }
    if(class_exists('\PHPMailer\PHPMailer\PHPMailer') && isset($t['email']) && \XLtrace\Hades\is_emailaddress($t['email'])){
      /*debug*/ print "Send email to: ".$t['email']."\n";

      $mail = new \PHPMailer\PHPMailer\PHPMailer(true);

      foreach(array('CharSet','Ical','Timeout') as $act){
        if(isset($set[strtolower($act)])){ $mail->$act = $set[strtolower($act)]; }
      }

      if((isset($set['smtp']) && $set['smtp'] === TRUE) || isset($set['smtp-auth'])){
        if(isset($set['smtp-debug'])){
          /*fix*/ if(is_string($set['smtp-debug'])){ $set['smtp-debug'] = strtoupper($set['smtp-debug']); }
          switch($set['smtp-debug']){
            case FALSE: case 'OFF': $mail->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_OFF; break;
            case NULL: case 'CLIENT': $mail->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_CLIENT; break;
            case TRUE: case 'SERVER': default: $mail->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_SERVER;
          }
        }
        $mail->isSMTP();
        if(isset($set['smtp-auth'])){
          $mail->SMTPAuth = (is_bool($set['smtp-auth']) && $set['smtp-auth'] === TRUE ? TRUE : FALSE);
          $mail->SMTPSecure = (isset($set['tls']) ? \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS : \PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS);
          if(isset($set['smtp-options'])){ $mail->SMTPOptions = $set['smtp-options']; }
        }
        $mail->Host = $set['host'];
        if(isset($set['username'])){ $mail->Username   = $set['username']; }
        if(isset($set['password'])){ $mail->Password   = $set['password']; }
        $mail->Port = (isset($set['port']) && is_int($set['port']) ? $set['port'] : (FALSE ? 25 : (isset($set['tls']) ? 587 : 465))); //25, 456, 587
      }
      elseif(isset($set['sendmail']) && $set['sendmail'] === TRUE){
        $mail->isSendmail();
      }

      if(FALSE){ //smime signed mail
        $mail->sign(
          $set['crt'],
          $set['key'],
          (FALSE ? $set['spkp'] : NULL),
          $set['pem']
        );
      }
      //DKIM: https://github.com/PHPMailer/PHPMailer/blob/master/examples/DKIM_sign.phps

      //Recipients
      foreach(array('from'=>'setFrom','to'=>'addAddress','reply-to'=>'addReplyTo','cc'=>'addCC','bcc'=>'addBCC') as $v=>$m){
        if(isset($set[$v])){
          if(is_string($set[$v]) || (is_array($set[$v]) && isset($set[$v]['email'])) ){ $set[$v] = array($set[$v]); }
          if(is_array($set[$v])){foreach($set[$v] as $j=>$w){
            if(is_array($w) && isset($w['email']) && \XLtrace\Hades\is_emailaddress($w['email']) && isset($w['name'])){ $mail->$m($w['email'], $w['name']); }
            elseif(is_string($w) && \XLtrace\Hades\is_emailaddress($w)){ $mail->$m($w); }
          }}
        }
      }
      if(isset($set['confirmreadingto']) && \XLtrace\Hades\is_emailaddress($set['confirmreadingto'])){
        $mail->ConfirmReadingTo = $set['confirmreadingto'];
        $mail->AddCustomHeader( "X-Confirm-Reading-To: ".$set['confirmreadingto'] );
        $mail->AddCustomHeader( "Return-Receipt-To: ".$set['confirmreadingto'] );
        $mail->AddCustomHeader( "Disposition-Notification-To: ".$set['confirmreadingto'] );
      }
      if(isset($t['name'])){ $mail->addAddress($t['email'], $t['name']); } else { $mail->addAddress($t['email']); }

      // Attachments
      if(isset($set['attachment'])){
        if(!is_array($set['attachment'])){ $set['attachment'] = array($set['attachment']); }
        foreach($set['attachment'] as $j=>$a){
          if(is_array($a) && isset($a['src']) && file_exists($a['src']) && isset($a['name'])){ $mail->addAttachment($a['src'], $a['name']); }
          elseif(is_string($a) && file_exists($a)){ $mail->addAttachment($a); }
        }
      }

      // Content
      $mail->isHTML(true);
      $mail->Subject = $title;
      //$mail->msgHTML(file_get_contents('contents.html'), __DIR__);
      $mail->Body    = $message; //\XLtrace\Hades\encapsule($message, FALSE, (isset($set['template']) ? $set['template']  : 'email.html'));
      $mail->AltBody = trim($message); //todo: html clean

      if(!isset($_GET['debug'])){ $mail->send(); } else { print_r($mail); }

      //save on imap like gmail: https://github.com/PHPMailer/PHPMailer/blob/master/examples/gmail.phps

      $count++;
    }
  }
  return (((is_bool($set) && $set === TRUE) || (isset($set['preview']) && $set['preview'] === TRUE)) ? /*\XLtrace\Hades\encapsule($message, FALSE)*/$message : $count);
}

/**********************************************************************/
/**********************************************************************/
/**********************************************************************/
/**********************************************************************/
class oldjunk extends module {
    var $path;
    var $patch;

    /*deprecated*/ public static function static_mirror_file(){ return \XLtrace\Hades\static_mirror_file(); }
    /*deprecated*/ public static function hermes_file(){ return \XLtrace\Hades\hermes_file(); }
    /*deprecated*/ public static function addressbook_file(){ return \XLtrace\Hades\addressbook_file(); }
    /*deprecated*/ public static function alias_file(){ return \XLtrace\Hades\alias_file(); }
    /*deprecated*/ public static function slaves_file(){ return \XLtrace\Hades\slaves_file(); }
    /*deprecated*/ public static function mailbox_file(){ return \XLtrace\Hades\mailbox_file(); }
    /*deprecated*/ public static function whitelist_file(){ return \XLtrace\Hades\whitelist_file(); }
    /*deprecated*/ public static function short_file(){ return \XLtrace\Hades\short_file(); }
    /*deprecated*/ public static function hermes_default_remote(){ return HERMES_REMOTE; }
    /*deprecated*/ public static function raw_git_path(){ return 'https://raw.githubusercontent.com/xltrace/static-mirror/master/'; }
    /*deprecated*/ public static function git_src(){ return 'https://github.com/xltrace/static-mirror'; }

    function get($for=NULL, &$set=array()){
        if(isset($_POST['m'])){ if(\XLtrace\Hades\authenticate_by_hash($_POST['m'])){ $_SESSION['m'] = $_POST['m']; } } elseif(isset($_GET['m'])){ if(\XLtrace\Hades\authenticate_by_hash($_GET['m'])){ $_SESSION['m'] = $_GET['m']; } }
        if(defined('HADES_MODULES') && !in_array(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for)), array('initial','update','upgrade','signin','signoff','status.json'))){
          $l = explode('|', HADES_MODULES);
          foreach($l as $i=>$mod){
            if(class_exists($mod) && method_exists($mod, 'detect')){
              $buffer = $mod::detect($for);
              if($buffer !== FALSE){ \XLtrace\Hades\encapsule($buffer, NULL); return TRUE; }
            }
          }
        }
        switch(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for))){
            case 'initial': self::initial(); break;
            case 'backup': self::backup(); break;
            case 'update': self::update(); break;
            case 'upgrade': self::upgrade(); break;
            case 'signin': case 'authenticate': case 'login': return \XLtrace\Hades\signin(); break;
            case 'signoff': case 'signout': case 'logout': return \XLtrace\Hades\signoff(); break;
            case 'configure': self::configure(); break;
            case 'management': self::management(); break;
            case 'duplicate': self::duplicate(); break;
            case 'decrypt': self::decrypt_module(); break;
            case 'hit': self::hermes_hit(); break;
            case 'mailbox': self::mailbox(); break;
            case '404': case 'hermes': case 'hermes.json': case basename(\XLtrace\Hades\alias_file()): case basename(\XLtrace\Hades\hermes_file()): case basename(\XLtrace\Hades\addressbook_file()): case basename(\XLtrace\Hades\slaves_file()): case basename(\XLtrace\Hades\mailbox_file()): case basename(\XLtrace\Hades\short_file()): case basename(\XLtrace\Hades\static_mirror_file()):
                header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; break;
            case 'status': self::status(); return FALSE; break;
            case 'status.json': header('content-type: application/json'); self::status_json(); return TRUE; break;
            default:
                if(isset($for) && strlen($for) > 0){
                    if(!self::alias($for, TRUE)){
                        $smdb = \XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array());
                        if(isset($smdb[$for])){ self::update($for); return TRUE; }
                        self::grab($for);
                    }
                    return TRUE;
                }
                else{
                    if(isset($this)){
                        $path = $this->path;
                        $patch = $this->patch;
                    }
                    else {
                        global $path, $patch;
                    }
                    if(!is_dir($path)){
                        #configure
                        self::initial();
                    }
                    #update
                    self::update();
                    return TRUE;
                }
        }
        return FALSE;
    }
    /*deprecated*/ public static function alias($path=NULL, $force=FALSE){ deprecated(__METHOD__);
        return FALSE;
    }
    /*deprecated*/ public static function grab($for){ deprecated(__METHOD__);
        return FALSE;
    }
    /*deprecated*/ public static function url_patch($str, $find=NULL, $host=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\url_patch($str, $find, $host); }
    /*deprecated*/ public static function initial(){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function update($file='index.html'){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function apply_patch($raw=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\apply_patch($raw); }
    /*deprecated*/ public static function upgrade(){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function backup(){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function authenticated($email=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\authenticated($email); }
    /*deprecated*/ public static function signin(){ deprecated(__METHOD__);
        $s = self::status_json(FALSE);
        if($s['2ndFA'] === TRUE){ return self::requestaccess(); }
        else{
          $html = '<form method="POST"><table><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Sign in" /></td></tr></table></form>';
          \XLtrace\Hades\encapsule($html, NULL);
          return FALSE;
        }
    }
    /*deprecated*/ public static function signoff(){ deprecated(__METHOD__); return \XLtrace\Hades\signoff(); }
    //public static function process_requestaccess(){}
    /*deprecated*/ public static function is_whitelisted($email=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\is_whitelisted($email); }
    /*deprecated*/ public static function authenticate_by_hash($m=NULL, $key=NULL, $email=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\authenticate_by_hash($m, $key, $email); }
    /*deprecated*/ public static function get_user_emailaddress(){ deprecated(__METHOD__); return self::get_element_from_2ndfa('e'); }
    /*deprecated*/ public static function get_element_from_2ndfa($el='e', $m=NULL, $key=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\get_element_from_2ndfa($el, $m, $key); }
    /*deprecated*/ public static function get_m_by_short($short){ deprecated(__METHOD__); return \XLtrace\Hades\get_m_by_short($short); }
    /*deprecated*/ public static function put_short_by_m($m){ deprecated(__METHOD__); return \XLtrace\Hades\put_short_by_m($m); }
    /*deprecated*/ public static function library(){ deprecated(__METHOD__); return \XLtrace\Hades\library(); }
    /*deprecated*/ public static function large_base_convert($numstring, $frombase, $tobase, $bitlength=0, $minlength=0){ deprecated(__METHOD__); return \XLtrace\Hades\large_base_convert($numstring, $frombase, $tobase, $bitlength, $minlength); }
    /*deprecated*/ public static function generate_m_hash($emailaddress=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\generate_m_hash($emailaddress); }
    /*deprecated*/ public static function requestaccess($emailaddress=NULL){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function requestaccess_email_html($set=array()){ deprecated(__METHOD__); return NULL; }
    /*deprecated*/ public static function notfound($for=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\notfound($for); }
    /*deprecated*/ public static function get_size($path=STATIC_MIRROR_BASE, $recursive=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\get_size($path, $recursive); }
    /*deprecated*/ public static function count_pages($path=FALSE, $ext=FALSE, $sitemap=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\count_pages($path, $ext, $sitemap); }
    /*deprecated*/ public static function status(){ deprecated(__METHOD__); return \XLtrace\Hades\module_get('status', 'status.json'); }
    /*deprecated*/ public static function status_html($set=array(), $with_style=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\module_get('status', 'status', $set); }
    /*deprecated*/ public static function status_json($print=TRUE){ deprecated(__METHOD__); return \XLtrace\Hades\module_get('status', 'status.json', $print); }
    /*deprecated*/ public static function current_URI($el=NULL, $pl=NULL, $set=array()){ deprecated(__METHOD__); return \XLtrace\Hades\current_URI($el, $pl, $set); }
    /*deprecated*/ public static function configure(){ deprecated(__METHOD__); return FALSE; }
    public static function management(){
        $success = \XLtrace\Hades\authenticated();
        if($success !== TRUE){ return \XLtrace\Hades\signin(); }
        $html = "<h2>Management module</h2>";
        //edit slaves.json = [ url, url ]
        //edit hermes.json = {"url": url, "key": key}
        //actions: upgrade, update, backup
        print $html; $html = NULL;
        foreach(array('toc','duplicate','decrypt_module') as $i=>$el){
          print self::$el();
        }
        \XLtrace\Hades\encapsule($html, NULL);
        return FALSE;
    }
    function toc($as_html=TRUE){
        $list = array(
          'update'=>'Update cache',
          'status.json' => 'status.json',
          '#1' => 'Administrator',
          'configure' => 'Configuration',
          'management' => 'Management Module',
          'upgrade'=>'Upgrade static-mirror',
          'duplicate' => 'Duplication Module'
        );
        $html = NULL;
        if($as_html === TRUE){
          foreach($list as $key=>$name){
            switch(substr($key, 0, 1)){
              case '#': $html .= '<li>'.$name.'</li>'; break;
              default: $html .= '<li><a href="'.$key.'">'.$name.'</a></li>';
            }
          }
          $html = '<ul>'.$html.'</ul>';
        }
        return ($as_html === TRUE ? $html : $list);
    }
    /*deprecated*/ public static function duplicate(){ deprecated(__METHOD__); return FALSE; }
    /*deprecated*/ public static function decrypt_module(){ deprecated(__METHOD__); return \XLtrace\Hades\module_get('management', 'decrypt'); }
    public static function hermes_hit(){
        \XLtrace\Hades\encapsule(self::hermes('hit', TRUE), NULL);
        return FALSE;
    }
    /*deprecated*/ public static function url_is_valid_status_json($url){ deprecated(__METHOD__); return \XLtrace\Hades\url_is_valid_status_json($url); }
    /*deprecated*/ public static function encapsule($content=NULL, $print=TRUE, $template='empty.html'){ deprecated(__METHOD__); return \XLtrace\Hades\encapsule($content, $print, $template); }
    /*deprecated*/ public static function run_slaves($action=NULL, $list=array()){ //herhaps the naming is politically incorrect; should be changed!
      deprecated(__METHOD__); return \XLtrace\Hades\run_slaves($action, $list);
    }
    /*deprecated*/ public static function build_url($ar=array()){ deprecated(__METHOD__); return \XLtrace\Hades\build_url($ar); }
    /*deprecated*/ public static function morph($str=NULL, $set=array()){ deprecated(__METHOD__); return \XLtrace\Hades\morph($str, $set); }
    /*deprecated*/ public static function emailaddress_array2str($to=array()){ deprecated(__METHOD__); return \XLtrace\Hades\emailaddress_array2str($to); }
    /*deprecated*/ public static function emailaddress_str2array($str=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\emailaddress_str2array($str); }
    /*deprecated*/ public static function emailaddress_autocomplete($to=array(), $set=TRUE, $tag="email"){ deprecated(__METHOD__); return \XLtrace\Hades\emailaddress_autocomplete($to, $set, $tag); }
    /*deprecated*/ public static function array_filter($set=array(), $match=array(), $limit=array(), &$rid=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\array_filter($set, $match, $limit, $rid); }
    /*deprecated*/ public static function tag_array_unique($tag="email", $to=array(), $merge=array()){ deprecated(__METHOD__); return \XLtrace\Hades\tag_array_unique($tag, $to, $merge); }
    /*deprecated*/ public static function mailbox(){ deprecated(__METHOD__); return \XLtrace\Hades\module_get('cockpit', 'mailbox'); }
    /*deprecated*/ public static function compose_mail_html($set=array()){ deprecated(__METHOD__); return \XLtrace\Hades\module\cockpit::compose_mail_html($set); }
    /*deprecated*/ public static function send_mail($title=NULL, $message=NULL, $to=FALSE, $set=array()){ deprecated(__METHOD__); return \XLtrace\Hades\send_mail($title, $message, $to, $set); }
    /*deprecated*/ public static function is_emailaddress($email=NULL){ deprecated(__METHOD__); return \XLtrace\Hades\is_emailaddress($email); }
    /*deprecated*/ public static function hermes($path=FALSE, $mode=FALSE, $addpostget=TRUE){ deprecated(__METHOD__); return \XLtrace\Hades\hermes($path, $mode, $addpostget); }
    /*deprecated*/ public static function encrypt($str, $key=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\encrypt($str, $key); }
    /*deprecated*/ public static function decrypt($ciphertext, $key=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\decrypt($ciphertext, $key); }
    /*deprecated*/ public static function json_encode($value, $options=0, $depth=512){ deprecated(__METHOD__); return \XLtrace\Hades\json_encode($value, $options, $depth); }
    /*deprecated*/ public static function array_urlencode($ar=array(), $sub=FALSE, $implode=TRUE){ deprecated(__METHOD__); return \XLtrace\Hades\array_urlencode($ar, $sub, $implode); }
    /*deprecated*/ public static function file_get_json($file, $as_array=TRUE, $def=FALSE){ deprecated(__METHOD__); return \XLtrace\Hades\file_get_json($file, $as_array, $def); }
    /*deprecated*/ public static function file_put_json($file, $set=array()){ deprecated(__METHOD__); return \XLtrace\Hades\file_put_json($file, $set); }
}
/**********************************************************************/
/**********************************************************************/
class static_mirror extends oldjunk {

}
/**********************************************************************/
/**********************************************************************/
function module_var_list(){ return array('mode','mapper','root','for','path','patch','standalone'); }
class module {
  var $for = NULL;
  var $set = array();
  var $mode = "text/markdown";
  var $mapper = FALSE; // __FILE__ .json
  var $root = FALSE;
  var $standalone = TRUE;
  function __construct($settings=array()){
    foreach(\Xltrace\Hades\module_var_list() as $el){
      if(isset($settings[$el]) && isset($this->$el)){ $this->$el = $settings[$el]; }
    }
    if($this->root == FALSE && $this->mapper !== FALSE){ $this->root = dirname($this->mapper); }
    /*fix*/ if($this->root !== FALSE && substr($this->root, -1) != '/'){ $this->root .= '/'; }
  }
  function __toString(){
    return $this->get($this->for, $this->set);
  }
  function get($for=NULL, &$set=array()){
    $str = FALSE;
    switch(strtolower($for)){
      case 'toc': $str = $this->toc(); break;
      case 'sitemap.xsl': $str = \XLtrace\Hades\module_get('sitemap','sitemap.xsl'); $this->mode = 'application/xsl'; break;
      default:
        $ext = FALSE; if(preg_match('#\.([a-z0-9]+)$#', $for, $buff)){ $ext = $buff[1]; }
        if($this->mapper !== FALSE && in_array($ext, array('xml','json','xsl','html')) && $for == substr($this->get_sitemap_URI(TRUE), 0, -3).$ext){
          $str = \XLtrace\Hades\module_get('sitemap','sitemap.'.$ext,$this->mapper_sitemap_json()); $this->mode = 'application/'.$ext;
        }
        else{
          $db = $this->mapper_set(NULL);
          if(isset($db[strtolower($for)])){ $str = $this->mapper(strtolower($for)); }
        }
    }
    if($str != FALSE){ $this->for = $for; $this->set =& $set; }
    if($this->mode == "text/html" && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    return $str;
  }
  function detect($for=NULL, &$set=array()){
    if($this->mapper !== FALSE){
      $db = $this->mapper_set(NULL);
      return (in_array(strtolower($for), array('toc', $this->get_sitemap_URI(TRUE))) || isset($db[strtolower($for)]));
    }
    else{
      $r = $this->get($for); return (in_array($r, array(TRUE, FALSE, NULL)) ? $r : TRUE);
    }
  }
  function get_mode(){ return $this->mode; }
  function get_sitemap_URI($short=FALSE){
    $uri = FALSE;
    if($this->mapper !== FALSE){
      $uri = \XLtrace\Hades\current_URI(basename(str_replace('\\','/',get_class($this))).'-sitemap.xml');
      if($short !== FALSE){ $uri = substr(parse_url($uri, PHP_URL_PATH),1); }
    }
    return $uri;
  }
  function toc($as_html=FALSE){
    $db = $this->mapper_set(NULL);
    $toc = NULL;
    foreach($db as $i=>$item){
      $toc .= '- ['.(isset($item['title']) ? $item['title'] : ucfirst($i)).']('.static_mirror::current_URI($i).')'."\n";
    }
    if($as_html === TRUE && function_exists('\Morpheus\markdown_decode')){ $toc = \Morpheus\markdown_decode($toc); }
    return $toc;
  }
  /*deprecated*/ function morph_template($template=NULL, $set=array(), $config=array()){ deprecated(__METHOD__); return \XLtrace\Hades\morph_template($template, $set, $config); }
  function mapper($for=NULL, $templates=NULL, &$set=array()){
    /*fix*/ if(!is_array($set)){ $set = array(); }
    /*fix*/ if($templates === NULL){ $templates = $this->mapper_set($for); } if($templates == array() ){ $templates = 'template_is_not_found'; }
    if(!is_array($templates)){ $templates = array('null'=>$templates); }
    if(isset($templates['authenticated']) && $templates['authenticated'] === TRUE && !static_mirror::authenticated()){ //force login!
      /*debug*/ print 'authenticated = '; print_r(array($templates['authenticated'], static_mirror::authenticated())); print "\n";
      //return self::morph_template('signin', array_merge($set, array('template-file'=>'signin')));
    }
    if(isset($templates['method'])){
      $res = $this->mapper_data($for, $set);
    } else { $res = NULL; }
    //*debug*/ print_r(array('for'=>$for,'templates'=>$templates,'set'=>$set,'res'=>$res));
    /*fix*/ if(is_bool($res)){ $res = ($res === TRUE ? 'true' : 'false'); } elseif($res === NULL){ $res = 'null'; }
    $t = (preg_match('#^[:](redirect|fwd)[\=](.*)$#i', $res) ? $res : (isset($templates[$res]) ? (is_string($templates[$res]) ? $templates[$res] : (is_array($templates[$res]) && isset($templates[$res]['template']) ? $templates[$res]['template'] : FALSE)) : FALSE));
    if(substr($t,0,1) == ':'){ //proces prefixed ':' references and redirects
      if(preg_match('#^[:](redirect|fwd)[\=](.*)$#i', $t, $buffer)){
        header("Location: ".static_mirror::current_URI($buffer[2]));
        print '<meta http-equiv="Refresh" content="0; url=\''.static_mirror::current_URI($buffer[2]).'\'" />';
        /*debug*/ print "REDIRECT to ".$buffer[2]." !\n";
        exit;
      }
      else{
        $res = substr($t,1);
        $t = (is_string($templates[$res]) ? $templates[$res] : (is_array($templates[$res]) && isset($templates[$res]['template']) ? $templates[$res]['template'] : FALSE));
      }
    }
    $this->mapper_output($for, $res, $set);
    /*fix*/ $set = array_merge($_GET, $_POST, $set);
    $set = array_merge($set, array('template-file'=>(isset($t) ? $t : $for)));
    //*debug*/print_r(array('res'=>$res,'t'=>$t,'templates'=>$templates,'set'=>$set));
    if(isset($t)){ return $this->morph_template($t, $set, $templates); }
    return $this->morph_template('template_is_not_found', $set);
  }
  function extentions(){
    return array('m','md','html');
  }
  function mapper_flags(){
    return array('authenticated','method','enctype','values','title');
  }
  function mapper_set($for=NULL){
    $set = array(
      'authenticate' => array('authenticated'=>FALSE,'method'=>'POST','null'=>'signin','true'=>'signin-success','false'=>'signin-failed'),
      'upload' => array('authenticated'=>TRUE,'method'=>'POST','enctype'=>'application/x-www-form-urlencoded','null'=>'upload','true'=>'upload-success','false'=>'upload-failed')
    );
    if(file_exists(preg_replace('#\.php$#', '.json', $this->mapper))){ $json = json_decode(file_get_contents(preg_replace('#\.php$#', '.json', $this->mapper)), TRUE); if(is_array($json)){ $set = $json; }}
    return ($for === NULL ? $set : (isset($set[strtolower($for)]) ? $set[strtolower($for)] : array()));
  }
  function mapper_sitemap_json($set=array()){
    $map = array();
    if(file_exists(preg_replace('#\.php$#', '.json', $this->mapper))){ $json = json_decode(file_get_contents(preg_replace('#\.php$#', '.json', $this->mapper)), TRUE); if(is_array($json)){ $set = $json; }}
    foreach($set as $k=>$s){
      $map[] = array('loc'=>\XLtrace\Hades\current_URI($k));
      //$map[] = \XLtrace\Hades\current_URI($k);
    }
    return $map;
  }
  function all_templates($all=TRUE, $create=FALSE, $extention='md'){
    $extentions = $this->extentions();
    $list = array();
    $db = $this->mapper_set(NULL);
    foreach($db as $i=>$item){
      foreach($item as $j=>$ho){
        $h = (is_string($ho) ? $ho : (isset($ho['template']) ? $ho['template'] : FALSE));
        if($h !== FALSE && !in_array($j, $this->mapper_flags())){
          if(substr($h,0,1) != ':'){
            $e = FALSE;
            foreach($extentions as $ext){
              $t = $this->root.$h.'.'.$ext;
              if(file_exists($t)){ $e = $t; }
            }
            if(($all !== TRUE ? $e === FALSE : TRUE)){
              $list[$i.':'.$j] = ($e === FALSE ? $this->root.$h.'.'.$extention : $e);
              if($create !== FALSE && !file_exists($list[$i.':'.$j])){ file_put_contents($list[$i.':'.$j], '<!-- '.$i.':'.$j.' = '.$h.' -->'); }
            }
          } else {
            //what to do with references and :redirect= ?
          }
        }
      }
    }
    return $list;
  }
  function mapper_output($for=NULL, $res=NULL, &$set=array()){
    /*fix*/ if(is_bool($res)){ $res = ($res === TRUE ? 'true' : 'false'); } elseif($res === NULL){ $res = 'null'; }
    switch(strtolower($for.':'.$res)){
      /*BEGIN mapper_output cases*/
      //case '': return TRUE; break;
      /*END mapper_output cases*/
      default:
        return FALSE; //do nothing
    }
    return FALSE;
  }
  function mapper_data($for=NULL, &$set=array()){
    $bool = NULL;
    $get = (isset($_GET) ? $_GET : array()); $post = $_POST;
    /*fix*/ if(isset($get['for']) && $for == $get['for']){ unset($get['for']); }
    if((isset($post) ? is_array($post) && count($post) == 0 : TRUE) && (is_array($get) && count($get) == 0)){ return NULL; }
    switch(strtolower($for)){
      /*BEGIN mapper_data cases*/
      //case '': return TRUE; break;
      /*END mapper_data cases*/
      default:
    }
    return NULL;
  }
}

if((defined('STATIC_MIRROR_ENABLE') ? STATIC_MIRROR_ENABLE : TRUE) && basename(dirname(__DIR__, 2)) != 'vendor'){
  //phpinfo(32); // $_SERVER['REQUEST_URI'] $_SERVER['SCRIPT_NAME'] $_SERVER['PHP_SELF']
  /*fix*/ if(!isset($_GET['for'])){$_GET['for'] = (isset($_SERVER['PHP_SELF']) ? substr($_SERVER['PHP_SELF'],1) : NULL);}
  $s = $settings = array('standalone'=>FALSE,'path'=>$path,'patch'=>$patch); foreach(\XLtrace\Hades\module_var_list() as $z){ if(!in_array($z, array('root','mapper','path','patch')) && isset($_GET[$z])){ $settings[$z] = $_GET[$z]; } }
  print \XLtrace\Hades\get($_GET['for'], $s, array('auth2ndFA','authenticate','status',array('module'=>'wiki','settings'=>array('root'=>__DIR__,'mode'=>'text/html','standalone'=>$settings['standalone'])),'maintenance','management','static_mirror'), $settings); exit;
}
?>
