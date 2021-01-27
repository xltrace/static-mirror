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
  if(!defined('STATIC_MIRROR_LIFESPAN')){ define('STATIC_MIRROR_LIFESPAN', 3600); }
  if(!defined('STATIC_MIRROR_SHORT_BASE')){ define('STATIC_MIRROR_SHORT_BASE', 36); }
  if(!defined('STATIC_MIRROR_SHORT_LENGTH')){ define('STATIC_MIRROR_SHORT_LENGTH', 8); }
  if(!defined('STATIC_MIRROR_ALLOW_MAIL')){ define('STATIC_MIRROR_ALLOW_MAIL', FALSE); }
  if(!defined('STATIC_MIRROR_BASE')){ define('STATIC_MIRROR_BASE', __DIR__); }
  if(!defined('HERMES_REMOTE')){ define('HERMES_REMOTE', 'http://fertilizer.wyaerda.nl/hermes/remote.php'); }

  if(class_exists('JSONplus')){ $_POST['raw'] = \JSONplus::worker('raw'); }
}
function get($for=NULL, &$set=array()){
  $sm = new static_mirror(STATIC_MIRROR_BASE);
  return $sm->detect($for, $set);
}
class static_mirror {
    var $path;
    var $patch;

    public static function static_mirror_file(){ return STATIC_MIRROR_BASE.'/static-mirror.json'; }
    public static function hermes_file(){ return STATIC_MIRROR_BASE.'/hermes.json'; }
    public static function addressbook_file(){ return STATIC_MIRROR_BASE.'/addressbook.json'; }
    public static function alias_file(){ return STATIC_MIRROR_BASE.'/alias.json'; }
    public static function slaves_file(){ return STATIC_MIRROR_BASE.'/slaves.json'; }
    public static function mailbox_file(){ return STATIC_MIRROR_BASE.'/mailbox.json'; }
    public static function whitelist_file(){ return STATIC_MIRROR_BASE.'/whitelist.json'; }
    public static function short_file(){ return STATIC_MIRROR_BASE.'/short.json'; }
    public static function hermes_default_remote(){ return HERMES_REMOTE; }
    public static function raw_git_path(){ return 'https://raw.githubusercontent.com/xltrace/static-mirror/master/'; }
    public static function git_src(){ return 'https://github.com/xltrace/static-mirror'; }

    function __construct($path, $patch=FALSE){
        $this->path = $path;
        $this->patch = ($patch === FALSE ? $this->path : $patch);
    }
    public static function detect($for=NULL){
        if(isset($_POST['m'])){ if(self::authenticate_by_hash($_POST['m'])){ $_SESSION['m'] = $_POST['m']; } } elseif(isset($_GET['m'])){ if(self::authenticate_by_hash($_GET['m'])){ $_SESSION['m'] = $_GET['m']; } }
        if(defined('HADES_MODULES') && !in_array(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for)), array('initial','update','upgrade','signin','signoff','status.json'))){
          $l = explode('|', HADES_MODULES);
          foreach($l as $i=>$mod){
            if(class_exists($mod) && method_exists($mod, 'detect')){
              $buffer = $mod::detect($for);
              if($buffer !== FALSE){ self::encapsule($buffer, TRUE); return TRUE; }
            }
          }
        }
        switch(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for))){
            case 'initial': self::initial(); break;
            case 'backup': self::backup(); break;
            case 'update': self::update(); break;
            case 'upgrade': self::upgrade(); break;
            case 'signin': case 'authenticate': case 'login': self::signin(); break;
            case 'signoff': case 'signout': case 'logout': self::signoff(); break;
            case 'configure': self::configure(); break;
            case 'management': self::management(); break;
            case 'duplicate': self::duplicate(); break;
            case 'decrypt': self::decrypt_module(); break;
            case 'hit': self::hermes_hit(); break;
            case 'mailbox': self::mailbox(); break;
            case '404': case 'hermes': case 'hermes.json': case basename(self::alias_file()): case basename(self::hermes_file()): case basename(self::addressbook_file()): case basename(self::slaves_file()): case basename(self::mailbox_file()): case basename(self::short_file()): case basename(self::static_mirror_file()):
                header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; break;
            case 'status': self::status(); return FALSE; break;
            case 'status.json': header('content-type: application/json'); self::status_json(); return TRUE; break;
            default:
                if(isset($for) && strlen($for) > 0){
                    if(!self::alias($for, TRUE)){
                        $smdb = self::file_get_json(self::static_mirror_file(), TRUE, array());
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
    public static function alias($path=NULL, $force=FALSE){
        /*fix*/ if($path === NULL){ $path = $_SERVER['REQUEST_URI']; }
        /*fix*/ if(substr($path, 0,1) == '/'){ $path = substr($path, 1); }

        $preg = '#^[\?]?(http[s]?|ftp)#';

        if(file_exists(self::alias_file())){
          $db = self::file_get_json(self::alias_file(), TRUE, array());
        } else { return FALSE; }

        if(isset($db[strtolower($path)])){
          $path = (isset($db['#']) && preg_match($preg, $db['#']) ? $db['#'].(in_array(substr($db['#'], -1), array('/','=','?',':','#','~') ) ? NULL : '/'): NULL).$db[strtolower($path)];
        }

        if(preg_match($preg, $path)){ $url = substr($path, 1); }
        elseif(isset($db['*']) && preg_match($preg, $db['*'])){ $url = substr($db['*'], 1).(in_array(substr($db['*'], -1), array('/','=','?',':','#','~') ) ? NULL : '/').$path; }
        else{ return FALSE; }

        /*fix*/ if(preg_match("#^(.*)index\.html$#", $url, $buffer)){ $url = $buffer[1]; }

        if($force !== FALSE){
          if(!isset($hermes) || $hermes !== FALSE){ self::hermes($path); }
          /*REDIRECTING*/
          header("HTTP/1.1 301 Moved Permanently");
          header("Location: ".$url);
          print '<html>You will be redirected to <a href="'.$url.'">'.$url.'</a>.</html>';
          exit;
        }
        return $url;
    }
    public static function grab($for){
        $allow_patch = FALSE;
        if(isset($this)){
            $path = $this->path;
            $patch = $this->patch;
        }
        else {
            global $path, $patch;
        }
        #gather
        #$for = $_GET['for'];

        $hermes = FALSE;

        /*fix*/ if(preg_match('#[\?]#', $for)){ $for = substr($for, 0, strpos($for, '?')); }

        if(substr($for, -1) == '/'){
            if(in_array(basename($for), array('/',''))){
                $alias = 'index.html';
            } else {
                $alias = basename(substr($for, 0, -1)).'.html';
            }
        } else { $alias = basename($for); }

        /*
        $log = $for."\t".$alias."\n";
        $handle = fopen(STATIC_MIRROR_BASE.'/gather.log', 'a');
        fwrite($handle, $log);
        fclose($handle);
        // print $log; exit;
        //*/

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
        switch(preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias)){
            case 'css': header('content-type: text/css'); break;
            case 'eot': header('content-type: application/vnd.ms-fontobject'); break;
            case 'gif': header('content-type: image/gif'); break;
            case 'htm': case 'html': header('content-type: text/html'); $hermes = TRUE; $allow_patch = TRUE; break;
            case 'ico': header('content-type: image/vnd.microsoft.icon'); break;
            case 'jpg': case 'jpeg': header('content-type: image/jpeg'); break;
            case 'js': header('content-type: text/javascript'); break;
            case 'json': header('content-type: application/json'); break;
            case 'otf': header('content-type: font/otf'); break;
            case 'png': header('content-type: image/png'); break;
            case 'pdf': header('content-type: application/pdf'); $hermes = TRUE; break;
            case 'php': header("HTTP/1.0 404 Not Found"); self::hermes($for); return FALSE; break;
            case 'ppt': header('content-type: application/vnd.ms-powerpoint'); $hermes = TRUE; break;
            case 'pptx': header('content-type: application/vnd.openxmlformats-officedocument.presentationml.presentation'); $hermes = TRUE; break;
            case 'svg': header('content-type: image/svg+xml'); break;
            case 'ttf': header('content-type: font/ttf'); break;
            case 'txt': header('content-type: text/plain'); $hermes = TRUE; break;
            case 'woff': header('content-type: font/woff'); break;
            case 'woff2': header('content-type: font/woff2'); break;
            case 'xml': header('content-type: application/xml'); $hermes = TRUE; break;
            default: header("HTTP/1.0 404 Not Found"); self::hermes($for); self::notfound($for); return FALSE;
        }

        if(!isset($hermes) || $hermes !== FALSE){ self::hermes($for); }

        $G = $_GET; $P = $_POST; /*fix*/ if(isset($G['for'])){ unset($G['for']); } if(isset($P['raw']) && strlen($P['raw']) == 0){ unset($P['raw']); }
        if((function_exists('curl_init') && function_exists('curl_setopt') && function_exists('curl_exec')) && ((isset($G) && is_array($G) && count($G) > 0) || (isset($P) && is_array($P) && count($P) > 0))){
            //grab through CURL an uncached version, and do not cache
            $conf = self::file_get_json(self::static_mirror_file(), TRUE, array());
            $src = reset($conf);
            if(strlen($src) < 6){ header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; }
            $url = parse_url($src, PHP_URL_SCHEME).'://'.parse_url($src, PHP_URL_HOST).'/'.$for;

            $url = $url.'?'.self::array_urlencode($G);
            $ch = curl_init( $url );
            curl_setopt( $ch, CURLOPT_POST, 1);
            curl_setopt( $ch, CURLOPT_POSTFIELDS, self::array_urlencode($P));
            curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 1);
            curl_setopt( $ch, CURLOPT_HEADER, 0);
            curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1);
            $raw = curl_exec( $ch );

            if(strlen($raw) == 0){ header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; }
            if($allow_patch !== FALSE){ $raw = self::apply_patch($raw); }
            print self::url_patch($raw, $allow_patch);
        }
        elseif(file_exists($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias))){
            print self::url_patch(file_get_contents($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias)), $allow_patch);
        }
        elseif(file_exists($path.basename($for))){
            print self::url_patch(file_get_contents($path.$alias), $allow_patch);
        }
        else {
            $conf = self::file_get_json(self::static_mirror_file(), TRUE, array());
            $src = reset($conf);
            if(strlen($src) < 6){ header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; }
            $raw = file_get_contents(parse_url($src, PHP_URL_SCHEME).'://'.parse_url($src, PHP_URL_HOST).'/'.$for);
            if(strlen($raw) == 0){ header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; }
            if($allow_patch !== FALSE){ $raw = self::apply_patch($raw); }
            file_put_contents(__DIR__.'/cache/'.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias), $raw);
            //file_put_contents(__DIR__.'/cache/'.$alias, $raw);
            print self::url_patch($raw, $allow_patch);
        }
        return TRUE;
    }
    public static function url_patch($str, $find=NULL, $host=FALSE){
      if(is_bool($find)){ if($find === FALSE){ return $str; } else { $find = NULL; }}
      /*fix*/ $alt = $find;
      if($host === FALSE){ $host = $_SERVER['HTTP_HOST']; }
      if($find === NULL){
        $find = array('https://localhost/', 'http://localhost/');
        /*future upgrade: grab from patch/.preg*/
      }
      /*fix*/ if(is_string($find)){ $find = array($find); }
      if(is_array($find)){foreach($find as $i=>$el){
        $alt[$i] = (parse_url($el) !== FALSE ? self::current_URI(NULL, NULL, array_merge(parse_url($el), array('host'=>$host))) : $el);
      }}
      /* \/ fix*/
      if(is_array($find)){$ef=array();foreach($find as $i=>$el){ if(preg_match('#[/]#', $el)){ $ef[$i] = str_replace('/','\\/', $el); } $find = array_merge($find, $ef); }}
      if(is_array($alt)){$af=array();foreach($alt as $i=>$el){ if(preg_match('#[/]#', $el)){ $af[$i] = str_replace('/','\\/', $el); } $alt = array_merge($alt, $af); }}

      $str = str_replace($find, $alt, $str);
      return $str;
    }
    public static function initial(){
        if(isset($this)){
            $path = $this->path;
            $patch = $this->patch;
        }
        else {
            global $path, $patch;
        }

        self::hermes('initial');

        if(!is_dir($path)){ mkdir($path); chmod($path, 00755); }
        if(!is_dir($patch)){ mkdir($patch); chmod($patch, 00755); }
        if(!file_exists(__DIR__.'/.htaccess')){ file_put_contents(__DIR__.'/.htaccess', "RewriteEngine On\n\nRewriteCond %{HTTPS} !=on\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\nRewriteRule \.(php)\$ - [L]\n\nRewriteRule ^\$ /static-mirror.php?for=index.html [QSA,L]\nRewriteRule ^(.*) /static-mirror.php?for=\$1 [QSA,L]"); }
        if(!file_exists(__DIR__.'/static-mirror.json')){ file_put_contents(__DIR__.'/static-mirror.json', self::json_encode( (isset($_GET['src']) ? array($_GET['src']) : array()) )); }
        return TRUE;
    }
    public static function update($file='index.html'){
        if(!preg_match('#^[a-z0-9_\-]+\.html$#', $file)){ $file = 'index.html'; }
        if(isset($this)){
            $path = $this->path;
            $patch = $this->patch;
        }
        else {
            global $path, $patch;
        }

        self::hermes('update');
        if(isset($_GET['all'])){ self::run_slaves('update'); }

        if(!file_exists(__DIR__.'/static-mirror.json')){ echo "No MIRROR configured."; return FALSE; }

        $conf = self::file_get_json(self::static_mirror_file(), TRUE, array());
        if(isset($conf[$file])){ $src = $conf[$file]; }
        else{ $src = reset($conf); $file = 'index.html'; }

        if(!is_array($conf) || strlen($src) < 1){ echo "No MIRROR configured."; return FALSE; }

        if($file == 'index.html'){
        $list = scandir($path);
        foreach($list as $i=>$f){
            if(!preg_match('#^[\.]{1,2}$#', $f)){ unlink($path.$f); }
        }}

        $raw = file_get_contents($src);
        $raw = self::apply_patch($raw);

        file_put_contents($path.$file, $raw);
        print self::url_patch($raw);
        return $raw;
    }
    public static function apply_patch($raw=NULL){
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
    public static function upgrade(){
        $raw = file_get_contents(self::raw_git_path()."static-mirror.php");
        self::hermes('upgrade');
        if(isset($_GET['all'])){ self::run_slaves('upgrade'); }
        if(strlen($raw) > 10 && preg_match('#^[\<][\?]php\s#', $raw) && is_writable(__FILE__)){
            file_put_contents(__FILE__, $raw);
            foreach(array('.gitignore','README.md','composer.json','simple_html_dom.php') as $i=>$f){
                if(is_writable(__DIR__.'/'.$f)){ file_put_contents(__DIR__.'/'.$f, file_get_contents(self::raw_git_path().$f)); }
            }
            $html = "Upgrade complete";
            self::encapsule($html, TRUE);
            return TRUE;
        }
        else {
            $html = "Upgrade failed, try again!";
            self::encapsule($html, TRUE);
            return FALSE;
        }
    }
    public static function backup(){
        self::hermes('backup');
        if(isset($_GET['all'])){ self::run_slaves('backup'); }
        return FALSE;
    }
    public static function authenticated($email=NULL){
        if(!file_exists(self::hermes_file())){ return FALSE; }
        $json = self::file_get_json(self::hermes_file(), TRUE, array());
        @session_start();
        if(isset($_POST['token']) && $_POST['token'] == $json['key']){
            $_SESSION['token'] = $_POST['token'];
            return TRUE;
        }
        if(isset($_GET['m']) && self::authenticate_by_hash($_GET['m'], NULL, $email)){ $_SESSION['m'] = $_GET['m']; return TRUE; }
        if(isset($_SESSION['token']) && $_SESSION['token'] == $json['key']){ return TRUE; }
        elseif(isset($_SESSION['m'])){ return self::authenticate_by_hash($_SESSION['m'], NULL, $email); }
        return FALSE;
    }
    public static function signin(){
        $s = self::status_json(FALSE);
        if($s['2ndFA'] === TRUE){ return self::requestaccess(); }
        else{
          $html = '<form method="POST"><table><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Sign in" /></td></tr></table></form>';
          self::encapsule($html, TRUE);
          return FALSE;
        }
    }
    public static function signoff(){
        self::authenticated();
        unset($_SESSION['token']);
        unset($_SESSION['m']);
        $html = "Static-mirror has forgotton your authentication-token. You are succesfully signed off.";
        self::encapsule($html, TRUE);
        return FALSE;
    }
    //public static function process_requestaccess(){}
    public static function is_whitelisted($email=NULL){
      if(!file_exists(self::whitelist_file())){ return FALSE; }
      $json = self::file_get_json(self::whitelist_file(), TRUE, array());
      return (in_array($email, $json) ? TRUE : FALSE);
    }
    public static function authenticate_by_hash($m=NULL, $key=NULL, $email=NULL){
      /*fix*/ if($m === NULL && isset($_SESSION['m'])){ $m = $_SESSION['m']; }
      /*fix*/ if($m === NULL && isset($_POST['m'])){ $m = $_POST['m']; }
      /*fix*/ if($m === NULL && isset($_GET['m'])){ $m = $_GET['m']; }
      /*fix*/ if(isset($m) && preg_match('#\s#', $m)){ $m = str_replace(' ','+',$m); }
      /*short*/ if(strlen($m) == STATIC_MIRROR_SHORT_LENGTH){if($found = self::get_m_by_short($m)){ $m = $found; }}
      /*fix*/ if($key === NULL){ $key = self::file_get_json(self::hermes_file(), 'key', NULL); }
      $jsonstr = self::decrypt($m, $key);
      $data = json_decode($jsonstr, TRUE);
      $lifespan = STATIC_MIRROR_LIFESPAN;
      /*fix*/ if(!isset($_SERVER['REMOTE_ADDR'])){ $_SERVER['REMOTE_ADDR'] = '127.0.0.1'; }
      $ebool = TRUE;
      if($email !== NULL){ $ebool = (isset($data['e']) && $data['e'] == $email); }
      $status = ($ebool && is_array($data) && isset($data['e']) && isset($data['t']) && ($data['t']<=date('U') && $data['t']>=(date('U')-$lifespan)) && isset($data['i']) && $data['i'] == $_SERVER['REMOTE_ADDR'] ? TRUE : FALSE);
      //*debug*/ print '<pre>'; print_r(array('m'=>$m, 'str'=>$jsonstr, 'data'=>$data, 'status'=>$status)); print '</pre>';
      return $status;
    }
    public static function get_user_emailaddress(){ return self::get_element_from_2ndfa('e'); }
    public static function get_element_from_2ndfa($el='e', $m=NULL, $key=NULL){
      /*fix*/ if($m === NULL && isset($_SESSION['m'])){ $m = $_SESSION['m']; }
      /*fix*/ if($m === NULL && isset($_POST['m'])){ $m = $_POST['m']; }
      /*fix*/ if($m === NULL && isset($_GET['m'])){ $m = $_GET['m']; }
      /*fix: needs @session_start() */ self::authenticated();
      if($m === NULL || strlen($m) < 1){ return FALSE; }
      /*fix*/ if(isset($m) && preg_match('#\s#', $m)){ $m = str_replace(' ','+',$m); }
      /*short*/ if(strlen($m) == STATIC_MIRROR_SHORT_LENGTH){if($found = self::get_m_by_short($m)){ $m = $found; }}
      /*fix*/ if($key === NULL){ $key = self::file_get_json(self::hermes_file(), 'key', NULL); }
      $jsonstr = self::decrypt($m, $key);
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
    public static function get_m_by_short($short){
      $set = self::file_get_json(self::short_file(), TRUE, array());
      if(is_array($set)){foreach($set as $k=>$s){
        /*clean up old listings*/ if($s['t'] < (time() - STATIC_MIRROR_LIFESPAN )){ unset($set[$k]); }
        if($s['short'] == $short){ return $s['m']; }
      }}
      return FALSE;
    }
    public static function put_short_by_m($m){
      $short = substr(self::large_base_convert(md5($m), 16, STATIC_MIRROR_SHORT_BASE), 0, STATIC_MIRROR_SHORT_LENGTH);
      $set = self::file_get_json(self::short_file(), TRUE, array());
      /*clean up old listings*/ foreach($set as $k=>$s){ if(isset($s['t']) && $s['t'] < (time() - STATIC_MIRROR_LIFESPAN )){ unset($set[$k]); } }
      $set[] = array('t'=>time(),'short'=>$short,'m'=>$m);
      /*fix*/ $ns = array(); foreach($set as $k=>$s){ $ns[] = $s; } $set = $ns;
      self::file_put_json(self::short_file(), $set);
      return $short;
    }
    static public function library(){
        return "0123456789" #10
  			."abcdefghij" #20
  			."klmnopqrst" #30
  			."uvwxyzABCD" #40
  			."EFGHIJKLMN" #50
  			."OPQRSTUVWX" #60
  			."YZ-_+!@$%~" #70 (trustworthy up to base62 (10+26+26), backwards-compatible to base70 (pre Xnode v2.0 RC047) )
  			."\"#&'()*,./" #80
  			.":;<=>?[\\]^" #90
  			."`{|}" #95
  			."¡¢" #97
  			."£¤¥§©«¬®°±" #107
  			."µ¶»¼½¾¿ÆÐ×" #117
  			."Þßæçð÷ø \t\n"; #127
    }
    static public function large_base_convert ($numstring, $frombase, $tobase, $bitlength=0, $minlength=0) {
      //*error*/ if($frombase <= 1 || $tobase <= 1){ return $numstring; }
      /*fix*/ if(is_string($frombase)){ $frombase = (int) self::large_base_convert($frombase, 70, 10); }
      /*fix*/ if(is_string($tobase)){ $tobase = (int) self::large_base_convert($tobase, 70, 10); }
      //*debug*/ if($frombase == 1 || $tobase == 1) print '<!-- LBC: '.print_r(array($numstring, $frombase, $tobase, $bitlength, $minlength), TRUE).' -->';
      /*standard behaviour*/ if(is_int($numstring) && $numstring < 256 && $frombase <= 36 && $tobase <= 36 && !($frombase == $tobase)){ $result = base_convert($numstring, $frombase, $tobase); if($minlength !== 0 && strlen($result) < $minlength){ $result = str_repeat('0', $minlength-strlen($result)).$result; } return $result; }
  		if($bitlength===0){ $bitlength = strlen(self::large_base_convert(self::large_base_convert($frombase-1, 10, $frombase, -1), $frombase, $tobase, -1)); }
  		//$numstring .= ''; /*forced string fix*/
      $numstring = (string) $numstring;
      $chars = self::library();
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
    public static function generate_m_hash($emailaddress=NULL){
      $m = NULL;
      /*fix*/ if(!isset($_SERVER['REMOTE_ADDR'])){ $_SERVER['REMOTE_ADDR'] = '127.0.0.1'; }
      //*fix*/ if($emailaddress === NULL && isset($_POST['emailaddress'])){ $emailaddress = $_POST['emailaddress']; }
      $key = self::file_get_json(self::hermes_file(), 'key', FALSE);
      //if(self::is_whitelisted($emailaddress)){ # check if emailaddress exists within database
        $data = array('e'=>$emailaddress,'i'=>$_SERVER['REMOTE_ADDR'],'t'=>(int) date('U'));
        $jsonstr = json_encode($data);
        $m = self::encrypt($jsonstr, $key);
        $short = self::put_short_by_m($m);
      //}
      return $m;
    }
    public static function requestaccess($emailaddress=NULL){
      /*fix*/ if($emailaddress === NULL && isset($_POST['emailaddress'])){ $emailaddress = $_POST['emailaddress']; }
      $s = self::status_json(FALSE);
      if(FALSE && $s['2ndFA'] === FALSE){
        self::encapsule('Request Access is not allowed or able to do an 2<sup>nd</sup>FA method request', TRUE);
        return FALSE;
      }
      $mode = NULL;
      $key = self::file_get_json(self::hermes_file(), 'key', FALSE);
      if(isset($emailaddress)){
        $mode = 'request';
        if(self::is_whitelisted($emailaddress)){ # check if emailaddress exists within database
          $data = array('e'=>$emailaddress,'i'=>$_SERVER['REMOTE_ADDR'],'t'=>(int) date('U'));
          $jsonstr = json_encode($data);
          $m = self::encrypt($jsonstr, $key);
          $short = self::put_short_by_m($m);
          $fs = array_merge($data, array('data'=>$data, 'json'=>$jsonstr, 'short'=>$short, 'm'=>$m, 'l'=>strlen($m), 'sURI'=>self::current_URI(array('for'=>$_GET['for'],'m'=>$short)), 'mURI'=>self::current_URI(array('for'=>$_GET['for'],'m'=>$m)), 'URI'=>self::current_URI() ));
          //*debug*/ print '<pre>'; print_r($fs); print '</pre>';
          //*debug*/ print '<pre>'; $raw = str_repeat($data['e'],20); for($i=1;$i<=strlen($raw);$i++){ $j = self::encrypt(substr($raw, 0, $i), $key); print $i.".\t".strlen($j)."\t".number_format($i/strlen($j)*100 , 2)."%\t".$j."\n";} print '</pre>';
          # email by PHPMailer $data['e'] := self::current_URI($m)
          self::send_mail('Request of access by 2ndFA', self::requestaccess_email_html($fs), $emailaddress, $fs);
        } else { //emailaddress is not whitelisted!!
          $mode = 'request-failed';
        }
      } elseif(isset($_GET['m'])){
        $mode = 'receive';
        self::authenticate_by_hash($_GET['m'], $key);
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
      self::encapsule($html, TRUE);
      return FALSE;
    }
    public static function requestaccess_email_html($set=array()){
      $html = 'You have requested access to <a href="{URI|localhost}">{URI|localhost}</a>. Your access is being granted by this link: <a href="{sURI|localhost}">{sURI|}</a>';
      return self::m($html, $set);
    }
    public static function notfound($for=NULL){
        $html = "Error 404: Page not found.";
        if($for != NULL){ $html .= "\n\n".$for." is missing."; }
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function get_size($path=STATIC_MIRROR_BASE, $recursive=FALSE){
        $size = 0;
        $list = scandir($path);
        foreach($list as $i=>$f){
          if(!preg_match('#^[\.]{1,2}$#', $f)){
            if(is_dir($path.$f)){
              if($recursive !== FALSE){ $size += self::get_size($path.$f.'/', $recursive); }
            }
            else {
              $size += filesize($path.$f);
            }
          }
        }
        return $size;
    }
    public static function count_pages($path=FALSE, $ext=FALSE, $sitemap=FALSE){
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
    public static function status(){
        $s = self::status_json(FALSE);
        if(isset($s['system-fingerprint'])){ $html = self::status_html($s, TRUE); }
        else{
          $html = NULL; $header = TRUE;
          foreach($s as $key=>$set){ $html .= self::status_html($set, $header); $header = FALSE; }
        }
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function status_html($set=array(), $with_style=FALSE){
        if($with_style !== FALSE){ $str = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/all.min.css"/><link ref="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.1/css/brands.min.css"/><style>a { text-decoration: none; color: #555; } a:hover { text-decoration: underline; } a:hover i { opacity: 0.8; } .bigicon { font-size: 16pt; margin: 4px 2px; } .green { color: green; } .light-gray { color: #CCC; } .black { color: black; } .gray { color: gray; } .red { color: red; }</style>'; } else { $str = NULL; }

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

        return self::m($str, $set);
    }
    public static function status_json($print=TRUE){
        $json = FALSE;
        if(isset($_GET['all'])){ $json = self::run_slaves('status.json'); }
        $stat = array('cache-mod-upoch'=>@filemtime(__DIR__.'/cache/index.html'),'system-mod-upoch'=>filemtime(__DIR__.'/static-mirror.php'));
        $stat['cache-mod'] = date('c', $stat['cache-mod-upoch']);
        $stat['system-mod'] = date('c', $stat['system-mod-upoch']);
        $stat['cache-size'] = self::get_size(__DIR__.'/cache/', TRUE);
        $stat['cache'] = ($stat['cache-mod-upoch'] == FALSE ? FALSE : TRUE);
        $stat['patch-size'] = self::get_size(__DIR__.'/patch/', TRUE);
        $stat['size'] = self::get_size(__DIR__.'/', TRUE);
        $stat['system-size'] = filesize(__DIR__.'/static-mirror.php');
        $stat['system-fingerprint'] = md5_file(__DIR__.'/static-mirror.php');
        $stat['htaccess'] = file_exists(__DIR__.'/.htaccess');
        $stat['htaccess-fingerprint'] = md5_file(__DIR__.'/.htaccess');
        $stat['curl'] = (!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec') ? FALSE : TRUE);
        $stat['hermes'] = (file_exists(self::hermes_file()) && $stat['curl']);
        if($stat['hermes'] === TRUE){
          $hermes = self::file_get_json(self::hermes_file(), TRUE, array());
          $stat['hermes-remote'] = preg_replace('#^[\?]#', '', $hermes['url']);
        }
        $stat['configured'] = file_exists(self::static_mirror_file());
        $stat['alias'] = file_exists(self::alias_file());
        if($stat['alias'] === TRUE){
          $alias = self::file_get_json(self::alias_file(), TRUE, array());
          if(isset($alias['#'])){ $stat['alias-domain'] = preg_replace('#^[\?]#', '', $alias['#']); }
          if(isset($alias['*'])){ $stat['alias-domain'] = preg_replace('#^[\?]#', '', $alias['*']); }
          $stat['alias-count'] = count($alias);
          $stat['alias-mod-upoch'] = @filemtime(self::alias_file());
          $stat['alias-mod'] = date('c', $stat['alias-mod-upoch']);
          $stat['alias-fingerprint'] = md5_file(self::alias_file());
        }
        $stat['mirror'] = count(self::file_get_json(self::static_mirror_file(), TRUE, array()));
        $stat['cache-count'] = (count(scandir(__DIR__.'/cache/')) - 2);
        $stat['pages'] = self::count_pages(__DIR__.'/cache/', array('html','htm','txt'));
        $stat['sitemap'] = self::count_pages(__DIR__.'/cache/', array('html','htm','txt'), TRUE);
        $stat['encapsule'] = (self::encapsule(NULL, FALSE) !== NULL);
        $stat['encapsule-size'] = strlen(self::encapsule(NULL, FALSE));
        $stat['addressbook'] = (file_exists(self::addressbook_file()) ? count(self::file_get_json(self::addressbook_file(), TRUE, array())) : FALSE);
        $stat['whitelist'] = (file_exists(self::whitelist_file()) ? count(self::file_get_json(self::whitelist_file(), TRUE, array())) : FALSE);
        $stat['force-https'] = (file_exists(__DIR__.'/.htaccess') ? (preg_match('#RewriteCond \%\{HTTPS\} \!\=on#', file_get_contents(__DIR__.'/.htaccess')) > 0 ? TRUE : FALSE) : FALSE);
        $stat['hades'] = (defined('HADES_MODULES') && TRUE); //future feature: have the hades system integrated into the non-static parts of this mirror, with use of the encapsule skin
        $stat['crontab'] = FALSE; //future feature: have crontab-frequency enabled to run update/upgrade/backup
        $stat['wiki'] = ($stat['hades'] && class_exists('\XLtrace\hades\module\wiki')); //future feature: HADES module WIKI (depends on JSONplus/markdown)
        $stat['slaves'] = (file_exists(self::slaves_file()) ? count(self::file_get_json(self::slaves_file(), TRUE, array())) : 0);
        $stat['2ndFA'] = $stat['mailbox'] = FALSE; /*placeholder*/
        $stat['cockpit'] = FALSE; //future feature: be able to send bulk-email to mailinglist.json based upon encapsule with custom content (requires PHPMailer)
        $stat['registery'] = FALSE; //future feature: allow visitors to leave their email-emailaddress in mailinglist.json
        $stat['active-mirror'] = FALSE; //future feature: enables active mirroring, for example when form-data is being committed. Form-data will be forwarded.
        $stat['backup'] = FALSE; //future feature: allow to backup the settings with the patch into an zip-file
        ksort($stat);
        $stat['URI'] = self::current_URI();
        $stat['composer'] = (file_exists(__DIR__.'/composer.json') && file_exists(__DIR__.'/vendor/autoload.php')); //future feature: upgrade components by composer
        $stat['composer-phar'] = (file_exists(__DIR__.'/composer.phar'));
        $stat['JSONplus'] = (class_exists('JSONplus'));
        if($stat['JSONplus'] === TRUE){
          $stat['markdown'] = class_exists('\JSONplus\markdown');
          $stat['qtranslate'] = class_exists('\JSONplus\qTranslate');
          $stat['morpheus'] = class_exists('\JSONplus\morpheus');
        }
        $stat['simple_html_dom'] = (file_exists(__DIR__.'/simple_html_dom.php') || class_exists('simple_html_dom_node'));
        $stat['PHPMailer'] = (class_exists('\PHPMailer\PHPMailer\PHPMailer') && STATIC_MIRROR_ALLOW_MAIL !== FALSE);
        $stat['mailbox'] = ($stat['PHPMailer'] && file_exists(self::mailbox_file()));
        $stat['2ndFA'] = ($stat['PHPMailer'] && $stat['mailbox'] && $stat['whitelist'] !== FALSE);
        /*debug*/ if(isset($_GET['system']) && $_GET['system'] == 'true'){ $stat = array_merge($stat, $_SERVER); }
        foreach(explode('|', 'SERVER_SOFTWARE|SERVER_PROTOCOL') as $i=>$s){ if(isset($_SERVER[$s])){ $stat[$s] = $_SERVER[$s]; } } #|HTTP_HOST
        if($json !== FALSE){
          $json[self::current_URI()] = $stat;
        }
        else{
          $json = $stat;
        }
        if($print === TRUE){
          print self::json_encode($json); exit;
          print FALSE;
        }
        else { return $json; }
    }
    public static function current_URI($el=NULL, $pl=NULL, $set=array()){
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
      return self::build_url($uri);
    }
    public static function configure(){
        if(!file_exists(self::hermes_file())){
            if(isset($_POST['token'])){
              $data = array('key'=>$_POST['token']);
              if(isset($_POST['url']) && (parse_url($_POST['url']) !== FALSE)){ $data['url'] = $_POST['url']; }
              file_put_contents(self::hermes_file(), str_replace('\/', '/', self::json_encode($data)));
              self::initial();
              return self::configure();
            }
            $html = '<form method="POST"><table><tr><td>Hermes remote:</td><td><input name="url" type="url" placeholder="'.self::hermes_default_remote().'" value="'.self::hermes_default_remote().'"/></td></tr><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Configure" /></td></tr></table></form>';
            self::encapsule($html, TRUE);
            return FALSE;
        }
        $success = self::authenticated(); // catch authenticated form data, so save token as cookie
        if($success !== TRUE){ return self::signin(); }
        $html = "Configure Static-Mirror";
        //edit static-mirror.json = { page: src, page: src } | where page="index.html"
        //edit patch (before/after)
        //edit patch (preg/html-dom)
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function management(){
        $success = self::authenticated();
        if($success !== TRUE){ return self::signin(); }
        $html = "<h2>Management module</h2>";
        //edit slaves.json = [ url, url ]
        //edit hermes.json = {"url": url, "key": key}
        //actions: upgrade, update, backup
        print $html; $html = NULL;
        foreach(array('toc','duplicate','decrypt_module') as $i=>$el){
          print self::$el();
        }
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function toc($as_html=TRUE){
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
    public static function duplicate(){
        $error = array();
        $success = self::authenticated();
        if($success !== TRUE){ return self::signin(); }
        $html = "Duplication Module";
        //edit slaves.json = [ url, url ]
        if(isset($_POST['path'])){ //duplicate static-mirror.php to $path
          $up = (defined('STATIC_MIRROR_DIRECTORY_UP') && is_int(STATIC_MIRROR_DIRECTORY_UP) ? STATIC_MIRROR_DIRECTORY_UP : 0);
          $chroot = ($up >= 1 ? dirname(__DIR__, $up) : __DIR__);
          /*fix*/ if(substr($chroot, -1) == '/'){ $chroot = substr($chroot, 0, -1); }
          $path = $_POST['path'];
          /*fix*/ if(substr($path, 0, 1) !== '/'){ $path = '/'.$path; }
          if(preg_match('#[\.]{2}#', $path)){ $error[] = $path.' could possibly go outside the chroot and is deemed invalid.'; }
          else{
            $map = $chroot.$path.(substr($path, -1) != '/' ? '/' : NULL);
            if(file_exists($map) && is_dir($map)){
              @file_put_contents($map.basename(__FILE__), file_get_contents(__FILE__));
              if(isset($_POST['activate']) && $_POST['activate'] == 'true'){
                @file_put_contents($map.basename(self::hermes_file()), file_get_contents(self::hermes_file()));
              }
            }
            else{ $error[] = $map.' does not exist.';}
          }
        }
        if(isset($_POST['slave'])){ //add slave
            $ns = $_POST['slave'];
            if(parse_url($ns) !== FALSE && strlen($ns) > 5){
              if(isset($_POST['activate']) && $_POST['activate'] == 'true'){
                file_get_contents($ns.'static-mirror.php?for=initial');
              }
              $slaves = self::file_get_json(self::slaves_file(), TRUE, array());
              /*fix*/ if(!is_array($slaves)){ $slaves = array(); }
              if(!in_array($ns, $slaves)){
                if(self::url_is_valid_status_json($ns)){
                  $slaves[] = $ns;
                  file_put_contents(self::slaves_file(), self::json_encode($slaves));
                } else { $error[] = $ns.' is not (yet) a valid static-mirror'; }
              }
              else { $error[] = $ns.' is already a slave'; }
            }
            else{ $error[] = $ns.' is not a valid url'; }
        }
        $debug = (FALSE ? print_r($_POST, TRUE).print_r($error, TRUE).print_r($notes, TRUE) : NULL);
        $html = $debug.'<form method="POST" action="duplicate"><table><tr><th colspan="2">'.$html.'</th></tr><tr><td>Path (on local server):</td><td><input name="path" placeholder="/domains/path/" /></td></tr><tr><td>Add as slave:</td><td><input type="url" name="slave" placeholder="https://" /></td></tr><tr><td><label><input type="checkbox" name="activate" value="true" checked="CHECKED"/> activate</label></td><td align="right"><input type="submit" value="Duplicate" /></td></tr></table>';
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function decrypt_module(){
        $error = array();
        $success = self::authenticated();
        if($success !== TRUE){ return self::signin(); }
        $html = "Decrypt Module";
        //edit slaves.json = [ url, url ]
        $result = NULL;
        if(isset($_POST['raw'])){ //duplicate static-mirror.php to $path
          $json = self::file_get_json(self::hermes_file(), TRUE, array());
          $tokens = (isset($_POST['tokens']) && strlen($_POST['tokens'])>0 ? $_POST['tokens'] : $json['key']);
          $result = self::decrypt(trim($_POST['raw']), explode(' ', preg_replace('#\s+#', ' ', $tokens)));
        }
        $debug = (FALSE ? print_r($_POST, TRUE).print_r($error, TRUE).print_r($result, TRUE) : NULL);
        $html = '<pre>'.$debug.'</pre><form method="POST" action="decrypt"><table><tr><th colspan="2">'.$html.'</th></tr><tr><td colspan="2"><textarea name="raw" style="width: 100%; min-width: 400px; min-height: 150px;">'.(isset($_POST['raw']) ? $_POST['raw'] : NULL).'</textarea></td></tr><tr><td>Tokens:</td><td><textarea name="tokens" style="width: 100%;">'.(isset($_POST['tokens']) ? $_POST['tokens'] : NULL).'</textarea></td></tr><tr><td colspan="2"><pre>'.$result.'</pre></td></tr><tr><td><label><input type="checkbox" name="commit" value="true" '.(isset($_POST['commit']) ? 'checked="CHECKED"' : NULL).'/> commit</label></td><td align="right"><input type="submit" value="Decrypt" /></td></tr></table></form>';
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function hermes_hit(){
        self::encapsule(self::hermes('hit', TRUE), TRUE);
        return FALSE;
    }
    public static function url_is_valid_status_json($url){
        if(parse_url($url) == FALSE || strlen($url) < 5){ return FALSE; }
        /*fix*/ if(substr($url, -1) == '/'){ $url = $url.'status.json'; }
        $raw = file_get_contents($url);
        if(strlen($raw) < 4){ return FALSE; }
        $json = json_decode($raw, TRUE);
        if(isset($json['system-fingerprint']) && strlen($json['system-fingerprint']) == 32){ return TRUE; }
        return FALSE;
    }
    public static function encapsule($content=NULL, $print=TRUE, $template='empty.html'){
        //encapsule when an cache/empty.html skin is available

        // $content = ''.$content.'';

        if($print === TRUE){ print $content; /*exit;*/ }
        return $content;
    }
    public static function run_slaves($action=NULL, $list=array()){ //herhaps the naming is politically incorrect; should be changed!
        if(!is_array($list) || count($list) == 0){
            if(!file_exists(self::slaves_file())){ return FALSE; }
            $list = self::file_get_json(self::slaves_file(), TRUE, array());
        }
        $bool = TRUE; $json = array();
        foreach($list as $i=>$url){
          $pu = parse_url($url);
          if($pu !== FALSE && is_array($pu)){
            switch(strtolower($action)){
              case 'upgrade': case 'update':
                $pu['path'] = $pu['path'].(substr($pu['path'], -1) ? NULL : '/').strtolower($action);
                $buffer = file_get_contents(self::build_url($pu));
                break;
              case 'status': case 'status.json':
                $pu['path'] = $pu['path'].(substr($pu['path'], -1) ? NULL : '/').'status.json';
                $json[$url] = self::file_get_json(self::build_url($pu));
                break;
              default:
                $bool = FALSE;
            }
          }
        }
        return (count($json) == 0 ? $bool : $json);
    }
    public static function build_url($ar=array()){
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
    public static function m($str=NULL, $set=array()){
      if(class_exists('\JSONplus\Morpeus')){ return \JSONplus\Morpheus::parse($str, $set); }
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
    public static function emailaddress_array2str($to=array()){
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
    public static function emailaddress_str2array($str=NULL){
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
    public static function emailaddress_autocomplete($to=array(), $set=TRUE, $tag="email"){
        $set = ($set === TRUE ? self::file_get_json(self::addressbook_file(), TRUE, array()) : (is_array($set) ? $set : array()) );
        foreach($to as $i=>$t){
          if(is_string($t)){ $to[$i] = self::array_filter($set, array($tag=>$t), 0); }
          elseif(is_array($t) && isset($t[$tag])){ $m = self::array_filter($set, array($tag=>$t[$tag]), 0); $to[$i] = array_merge($t, (is_array($m) ? $m : array())); }
        }
        return $to;
    }
    public static function array_filter($set=array(), $match=array(), $limit=array(), &$rid=NULL){
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
    public static function tag_array_unique($tag="email", $to=array(), $merge=array()){
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
    public static function mailbox(){
        $note = NULL;
        if(self::authenticated() !== TRUE){ return self::signin(); }
        $s = self::status_json(FALSE);
        if($s['PHPMailer'] === false){ return self::encapsule('Unable to send email.', TRUE); }
        $set = array();
        /*settings*/ $set = array_merge(self::file_get_json(self::mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
        $set['message'] = (isset($_POST['message']) ? $_POST['message'] : (isset($_GET['message']) ? $_GET['message'] : NULL));
        $set['title'] = (isset($_POST['title']) ? $_POST['title'] : (isset($_GET['title']) ? $_GET['title'] : NULL));
        // note you should proces $_POST['raw'] for commandline execution
        foreach(array('to','cc','bcc','reply-to','from') as $m){
          $set[$m] = (isset($_POST[$m]) ? array_merge((isset($set[$m]) && is_array($set[$m]) ? $set[$m] : array()), self::emailaddress_str2array($_POST[$m])) : (isset($set[$m]) ? $set[$m] : array() ));
          $set[$m] = self::tag_array_unique('email', $set[$m]);
          $set[$m] = self::emailaddress_autocomplete($set[$m]);
          if(in_array($m, array('reply-to','from'))){ $set[$m] = end($set[$m]); }
          $set[$m.'Str'] = self::emailaddress_array2str($set[$m]);
        }
        //*debug*/ print '<pre>'; print_r($set); print '</pre>';

        /*settings*/ $set = array_merge(self::file_get_json(self::mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
        $note = self::send_mail($set);

        //*debug*/ print '<pre>'; print_r($_POST); print_r($set); print '</pre>';
        $html = self::compose_mail_html(array_merge($set, array('notification'=>$note) ));
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function compose_mail_html($set=array()){
      return self::m('{notification|}<form method="POST" class="compose-mail">'
        .'<style>form.compose-mail label span { display: inline-block; min-width: 125px; } form.compose-mail span.fw { display: inline-block; width: 575px; } form.compose-mail textarea, form.compose-mail input[name=title] { width: 450px; height: 40px; min-height: 40px; box-sizing: border-box; margin: 2px; padding: 5px 8px; font-family: arial; font-size: 11pt; } form.compose-mail textarea { padding: 10px 14px; resize: vertical; } form.compose-mail textarea[name=message] { height: 200px; } form.compose-mail input[type=submit], form.compose-mail span.fw input { float: right; }</style>'

        .'<label for="to"><span>To: </span><textarea name="to" id="to" rows="1" cols="20" class="Emailaddress">{toStr|}</textarea></label><br>'
        .'<label for="cc"><span>CC: </span><textarea name="cc" id="cc" rows="1" cols="20" class="Emailaddress">{ccStr|}</textarea></label><br>'
        .'<label for="bcc"><span>BCC: </span><textarea name="bcc" id="bcc" rows="1" cols="20" class="Emailaddress">{bccStr|}</textarea></label><br>'

        .'<label for="title"><span>Title: </span><input type="text" name="title" id="title" value="{title|}" placeholder="Title"></label><br>'
        .'<label for="message"><span>Message: </span><textarea name="message" id="message" rows="8" cols="20" class="wysiwyg html">{message|}</textarea></label><br>'
        .'<span class="fw"><input type="submit" name="action" value="Send"/> <input type="button" name="action" value="Preview"/></span>'
        .'</form>', $set);
    }
    public static function send_mail($title=NULL, $message=NULL, $to=FALSE, $set=array()){
        if(defined('STATIC_MIRROR_ALLOW_MAIL') && STATIC_MIRROR_ALLOW_MAIL === FALSE){ return FALSE; } //deadswitch to disable mail
        $count = 0;
        /*fix*/ if(is_bool($set)){ $set = array('preview'=>$set); }
        /*fix*/ if(is_array($title)){ $set = array_merge($set, $title); $title = (isset($set['title']) ? $set['title'] : NULL); $message = (isset($set['message']) ? $set['message'] : $message); if($to === FALSE && isset($set['to'])){ $to = $set['to']; } }
        $set = array_merge(self::file_get_json(self::mailbox_file(), TRUE, array()), (is_array($set) ? $set : array()));
        //if(self::authenticated() !== TRUE){ return FALSE/*self::signin()*/; }
        if(is_string($message) && preg_match('#[\.](html|md)$#', $message, $ext)){
          $message = (file_exists($message) ? file_get_contents($message) : NULL); //grab $message
          switch($ext[1]){
            case 'md':
              $message = ($message); //parse markdown
              break;
            //case 'html': default: //do nothing to change input
          }
        }
        /* json / single or non addressy fix */ if(!is_array($to)){ if(is_string($to)){ $to = (preg_match('#^\s*[\[\{]#', $to) && preg_match('#[\]\}]\s*$#', $to) ? json_decode($to, TRUE) : self::emailaddress_str2array($to)); } else{ $to = array(); } }
        /*fix*/ if(isset($set['to'])){ $to = array_merge($to, $set['to']); }
        foreach($to as $i=>$t){
          if(is_string($t)){ $t = array('email'=>trim($t)); }
          if(class_exists('\PHPMailer\PHPMailer\PHPMailer') && isset($t['email']) && self::is_emailaddress($t['email'])){
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
                  if(is_array($w) && isset($w['email']) && self::is_emailaddress($w['email']) && isset($w['name'])){ $mail->$m($w['email'], $w['name']); }
                  elseif(is_string($w) && self::is_emailaddress($w)){ $mail->$m($w); }
                }}
              }
            }
            if(isset($set['confirmreadingto']) && self::is_emailaddress($set['confirmreadingto'])){
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
            $mail->Body    = self::encapsule($message, FALSE, (isset($set['template']) ? $set['template']  : 'email.html'));
            $mail->AltBody = trim($message); //todo: html clean

            if(!isset($_GET['debug'])){ $mail->send(); } else { print_r($mail); }

            //save on imap like gmail: https://github.com/PHPMailer/PHPMailer/blob/master/examples/gmail.phps

            $count++;
          }
        }
        return (((is_bool($set) && $set === TRUE) || (isset($set['preview']) && $set['preview'] === TRUE)) ? self::encapsule($message, FALSE) : $count);
    }
    public static function is_emailaddress($email=NULL){ return filter_var($email, FILTER_VALIDATE_EMAIL); }
    public static function hermes($path=FALSE, $mode=FALSE, $addpostget=TRUE){
        if(!file_exists(self::hermes_file())){ return FALSE; }
        if(!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec')){ $mode = NULL; }
        # $path + $url + $key
        $set = self::file_get_json(self::hermes_file(), TRUE, array());
        $url = (isset($set['url']) ? $set['url'] : self::hermes_default_remote());
        $key = (isset($set['key']) ? $set['key'] : FALSE);
        $message = array(
            "when"=>date('c'),
            "stamp"=>date('U'),
            "identity"=>substr(md5((isset($_SERVER['REMOTE_ADDR']) ? $_SERVER['REMOTE_ADDR'] : 'localhost')), 0, 24),
            "HTTP_HOST"=>self::current_URI(),
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
        if($key !== FALSE){ $message = self::encrypt($message, $key); }
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
    public static function encrypt($str, $key=FALSE){
        if(isset($this) && is_bool($key)){ $key = $this->secret; } elseif($key == NULL || is_bool($key)){ return $str; }
        $ivlen = openssl_cipher_iv_length($cipher="AES-128-CBC");
        $iv = openssl_random_pseudo_bytes($ivlen);
        $ciphertext_raw = openssl_encrypt($str, $cipher, $key, $options=OPENSSL_RAW_DATA, $iv);
        $hmac = hash_hmac('sha256', $ciphertext_raw, $key, $as_binary=true);
        $ciphertext = base64_encode( $iv.$hmac.$ciphertext_raw );
        return $ciphertext;
    }
    public static function decrypt($ciphertext, $key=FALSE){
      if(isset($this) && is_bool($key)){
        $key = $this->secret;
      }
      elseif(is_array($key)){
        $awnser = FALSE;
        foreach($key as $i=>$k){
          $b = (isset($this) ? $this->decrypt($ciphertext, $k) : self::decrypt($ciphertext, $k) );
          if($b !== FALSE){
            $awnser = $b;
            if(isset($this)){
              $this->last = $k;
              $this->hit = array_unique(array_merge($this->hit, array($k)));
            } elseif(defined('JSONplus_KEY_LAST') && defined('JSONplus_KEY_HIT')) {
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
    public static function json_encode($value, $options=0, $depth=512){
      return (class_exists('JSONplus') ? \JSONplus::encode($value, $options, $depth) : json_encode($value, $options, $depth));
    }
    public static function array_urlencode($ar=array(), $sub=FALSE, $implode=TRUE){
        $set = array();
        foreach($ar as $k=>$value){
          $key = (is_bool($sub) ? $k : $sub.'['.$k.']');
          if(is_array($value)){
            $set = array_merge($set, self::array_urlencode($value, $key, FALSE));
          }
          else{
            $set[$key] = $key.'='.urlencode($value);
          }
        }
        return ($implode === TRUE ? implode('&', $set) : $set);
    }
    public static function file_get_json($file, $as_array=TRUE, $def=FALSE){
      /*fix*/ if(preg_match("#[\n]#", $file)){ $file = explode("\n", $file); }
      if(is_array($file)){
        $set = FALSE;
        foreach($file as $i=>$f){
          $buffer = self::file_get_json($f, $as_array, $def);
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
    public static function file_put_json($file, $set=array()){
      if(class_exists('JSONplus')){
        $jsonstr = \JSONplus::encode($set);
      }
      else{
        $jsonstr = json_encode($set);
      }
      return file_put_contents($file, $jsonstr);
    }
}
class module /*extends static_mirror*/ {
  var $for = NULL;
  var $mode = "text/markdown";
  var $mapper = FALSE; // __FILE__ .json
  var $root = FALSE;
  function __construct($settings=array()){
    foreach(array('mode','mapper','root','for') as $el){
      if(isset($settings[$el])){ $this->$el = $settings[$el]; }
    }
    if($this->root == FALSE && $this->mapper !== FALSE){ $this->root = dirname($this->mapper); }
    /*fix*/ if($this->root !== FALSE && substr($this->root, -1) != '/'){ $this->root .= '/'; }
  }
  function get($for=NULL, &$set=array()){
    $str = FALSE;
    switch(strtolower($for)){
      case 'toc': $str = $this->toc(); break;
      default:
        $db = $this->mapper_set(NULL);
        if(isset($db[strtolower($for)])){ $str = $this->mapper(strtolower($for)); }
    }
    if($this->mode == "text/html" && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    return $str;
  }
  /*public static*/ function detect($for=NULL, &$set=array()){
    if($this->mapper !== FALSE){
      $db = $this->mapper_set(NULL);
      return (in_array(strtolower($for), array('toc')) || isset($db[strtolower($for)]));
    }
    else{
      $r = $this->get($for); return (in_array($r, array(TRUE, FALSE, NULL)) ? $r : TRUE);
    }
  }
  /*public static*/ function toc($as_html=FALSE){
    $db = $this->mapper_set(NULL);
    $toc = NULL;
    foreach($db as $i=>$item){
      $toc .= '- ['.(isset($item['title']) ? $item['title'] : ucfirst($i)).']('.static_mirror::current_URI($i).')'."\n";
    }
    if($as_html === TRUE && function_exists('\Morpheus\markdown_decode')){ $toc = \Morpheus\markdown_decode($toc); }
    return $toc;
  }
  function mm($template=NULL, $set=array(), $config=array()){
    $extentions = array('m','md','html');
    foreach($extentions as $ext){
    $t = $this->root.$template.'.'.$ext;
    //*debug*/ print '<pre>'; print_r(array('template'=>$template,'set'=>$set,'config'=>$config,'t'=>$t,'t_exists'=>file_exists($t))); print '</pre>';
    if(file_exists($t)){
      $raw = file_get_contents($t);
      $raw = static_mirror::m($raw, $set);
      //*markdown fix*/ $raw = \Morpheus\Markdown_decode($raw, array_merge($set, $config)); //$morph = new \Morpheus\markdown(); $raw = $morph->decode($raw, array_merge($set, $config)); //print_r($morph);
      //*debug*/ print_r($raw); exit;
      return $raw;
    }}
    return (file_exists($this->root.'template_is_not_found.html') ? $this->mm('template_is_not_found', $set) : FALSE);
  }
  function mapper($for=NULL, $templates=NULL, &$set=array()){
    /*fix*/ if(!is_array($set)){ $set = array(); }
    /*fix*/ if($templates === NULL){ $templates = $this->mapper_set($for); } if($templates == array() ){ $templates = 'template_is_not_found'; }
    if(!is_array($templates)){ $templates = array('null'=>$templates); }
    if(isset($templates['authenticated']) && $templates['authenticated'] === TRUE && !static_mirror::authenticated()){ //force login!
      /*debug*/ print 'authenticated = '; print_r(array($templates['authenticated'], static_mirror::authenticated())); print "\n";
      //return self::mm('signin', array_merge($set, array('template-file'=>'signin')));
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
    if(isset($t)){ return $this->mm($t, $set, $templates); }
    return $this->mm('template_is_not_found', $set);
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
  \XLtrace\Hades\get($_GET['for']);
}
?>
