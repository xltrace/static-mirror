<?php
namespace XLtrace;
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


$path = __DIR__.'/cache/';
$patch = __DIR__.'/patch/';

if(file_exists(__DIR__.'/vendor/autoload.php')){ require_once(__DIR__.'/vendor/autoload.php'); }
if(file_exists('simple_html_dom.php')){ require('simple_html_dom.php'); }

class static_mirror {
    var $path;
    var $patch;

    public static function static_mirror_file(){ return __DIR__.'/static-mirror.json'; }
    public static function hermes_file(){ return __DIR__.'/hermes.json'; }
    public static function slaves_file(){ return __DIR__.'/slaves.json'; }
    public static function hermes_default_remote(){ return 'http://fertilizer.wyaerda.nl/hermes/remote.php'; }
    public static function raw_git_path(){ return 'https://raw.githubusercontent.com/xltrace/static-mirror/master/'; }

    function __construct($path, $patch=FALSE){
        $this->path = $path;
        $this->patch = ($patch === FALSE ? $this->path : $patch);
    }
    public static function detect($for=NULL){
        switch(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for))){
            case 'initial': self::initial(); break;
            case 'backup': self::backup(); break;
            case 'update': self::update(); break;
            case 'upgrade': self::upgrade(); break;
            case 'signin': case 'authenticate': case 'login': self::signin(); break;
            case 'signoff': self::signoff(); break;
            case 'configure': self::configure(); break;
            case 'management': self::management(); break;
            case '404': case 'hermes': case 'hermes.json': case basename(self::hermes_file()): case basename(self::slaves_file()): case basename(self::static_mirror_file()):
                header("HTTP/1.0 404 Not Found"); self::notfound($for); return FALSE; break;
            case 'status.json': header('content-type: application/json'); self::status_json(); return FALSE; break;
            default:
                if(isset($for) && strlen($for) > 0){
                    self::grab($for);
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
        return TRUE;
    }
    public static function grab($for){
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
        $handle = fopen(__DIR__.'/gather.log', 'a');
        fwrite($handle, $log);
        fclose($handle);
        // print $log; exit;
        //*/

        // https://developer.mozilla.org/en-US/docs/Web/HTTP/Basics_of_HTTP/MIME_types/Common_types
        switch(preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias)){
            case 'css': header('content-type: text/css'); break;
            case 'eot': header('content-type: application/vnd.ms-fontobject'); break;
            case 'gif': header('content-type: image/gif'); break;
            case 'htm': case 'html': header('content-type: text/html'); $hermes = TRUE; break;
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

        if(file_exists($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias))){
            print file_get_contents($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias));
        }
        elseif(file_exists($path.basename($for))){
            print file_get_contents($path.$alias);
        }
        else {
            $conf = json_decode(file_get_contents(__DIR__.'/static-mirror.json'), TRUE);
            $src = reset($conf);
            if(strlen($src) < 6){ header("HTTP/1.0 404 Not Found"); return FALSE; }
            $raw = file_get_contents(parse_url($src, PHP_URL_SCHEME).'://'.parse_url($src, PHP_URL_HOST).'/'.$for);
            if(strlen($raw) == 0){ header("HTTP/1.0 404 Not Found"); return FALSE; }
            file_put_contents(__DIR__.'/cache/'.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias), $raw);
            //file_put_contents(__DIR__.'/cache/'.$alias, $raw);
            print $raw;
        }
        return TRUE;
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
        if(!file_exists(__DIR__.'/static-mirror.json')){ file_put_contents(__DIR__.'/static-mirror.json', json_encode( (isset($_GET['src']) ? array($_GET['src']) : array()) )); }
        return TRUE;
    }
    public static function update(){
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

        $conf = json_decode(file_get_contents(__DIR__.'/static-mirror.json'), TRUE);
        $src = reset($conf);

        if(!is_array($conf) || strlen($src) < 1){ echo "No MIRROR configured."; return FALSE; }

        $list = scandir($path);
        foreach($list as $i=>$f){
            if(!preg_match('#^[\.]{1,2}$#', $f)){ unlink($path.$f); }
        }

        $raw = file_get_contents($src);

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
                    }
                }
            }
        }

        file_put_contents($path.'index.html', $raw);
        print $raw;
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
    public static function authenticated(){
        if(!file_exists(self::hermes_file())){ return FALSE; }
        $json = json_decode(file_get_contents(self::hermes_file()), TRUE);
        session_start();
        if(isset($_POST['token']) && $_POST['token'] == $json['key']){
            $_SESSION['token'] = $_POST['token'];
            return TRUE;
        }
        if(isset($_SESSION['token']) && $_SESSION['token'] == $json['key']){ return TRUE; }
        return FALSE;
    }
    public static function signin(){
        $html = '<form method="POST"><table><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Sign in" /></td></tr></table></form>';
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function signoff(){
        self::authenticated();
        unset($_SESSION['token']);
        $html = "Static-mirror has forgotton your authentication-token. You are succesfully signed off.";
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function notfound($for=NULL){
        $html = "Error 404: Page not found.";
        if($for != NULL){ $html .= "\n\n".$for." is missing."; }
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function get_size($path=__DIR__, $recursive=FALSE){
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
    public static function status_json(){
        $json = FALSE;
        if(isset($_GET['all'])){ $json = self::run_slaves('status.json'); }
        $stat = array('cache-mod-upoch'=>@filemtime(__DIR__.'/cache/index.html'),'system-mod-upoch'=>filemtime(__DIR__.'/static-mirror.php'));
        $stat['cache-mod'] = date('c', $stat['cache-mod-upoch']);
        $stat['system-mod'] = date('c', $stat['system-mod-upoch']);
        $stat['cache-size'] = self::get_size(__DIR__.'/cache/', TRUE);
        $stat['patch-size'] = self::get_size(__DIR__.'/patch/', TRUE);
        $stat['size'] = self::get_size(__DIR__.'/', TRUE);
        $stat['system-size'] = filesize(__DIR__.'/static-mirror.php');
        $stat['system-fingerprint'] = md5_file(__DIR__.'/static-mirror.php');
        $stat['htaccess'] = file_exists(__DIR__.'/.htaccess');
        $stat['htaccess-fingerprint'] = md5_file(__DIR__.'/.htaccess');
        $stat['hermes'] = file_exists(self::hermes_file());
        $stat['configured'] = file_exists(self::static_mirror_file());
        $stat['mirror'] = count(json_decode(file_get_contents(self::static_mirror_file()), TRUE));
        $stat['cache-count'] = (count(scandir(__DIR__.'/cache/')) - 2);
        $stat['pages'] = self::count_pages(__DIR__.'/cache/', array('html','htm','txt'));
        $stat['sitemap'] = self::count_pages(__DIR__.'/cache/', array('html','htm','txt'), TRUE);
        $stat['encapsule'] = (self::encapsule(NULL, FALSE) !== NULL);
        $stat['encapsule-size'] = strlen(self::encapsule(NULL, FALSE));
        $stat['composer'] = (file_exists(__DIR__.'/composer.json') && file_exists(__DIR__.'/vendor/autoload.php')); //future feature: upgrade components by composer
        $stat['force-https'] = (file_exists(__DIR__.'/.htaccess') ? (preg_match('#RewriteCond \%\{HTTPS\} \!\=on#', file_get_contents(__DIR__.'/.htaccess')) > 0 ? TRUE : FALSE) : FALSE);
        $stat['hades'] = FALSE; //future feature: have the hades system integrated into the non-static parts of this mirror, with use of the encapsule skin
        $stat['crontab'] = FALSE; //future feature: have crontab-frequency enabled to run update/upgrade/backup
        $stat['slaves'] = (file_exists(self::slaves_file()) ? count(json_decode(file_get_contents(self::slaves_file()), TRUE)) : 0);
        ksort($stat);
        foreach(explode('|', 'SERVER_SOFTWARE|SERVER_PROTOCOL|HTTP_HOST') as $i=>$s){ $stat[$s] = $_SERVER[$s]; }
        //$stat = array_merge($stat, $_SERVER);
        if($json !== FALSE){
          $json[self::current_URI()] = $stat;
          print json_encode($json); exit;
        }
        else{
          print json_encode($stat); exit;
        }
        return FALSE;
    }
    public static function current_URI(){ return self::build_url(array('scheme'=>(($_SERVER['REQUEST_SCHEME']=='https' || (string) $_SERVER['SERVER_PORT'] == '443' || $_SERVER['HTTPS']=='on' || substr($_SERVER['SCRIPT_URI'],0,5)=='https') ? 'https' : 'http'), 'host'=>$stat['HTTP_HOST'])); }
    public static function configure(){
        if(!file_exists(self::hermes_file())){
            if(isset($_POST['token'])){
              $data = array('key'=>$_POST['token']);
              if(isset($_POST['url']) && (parse_url($_POST['url']) != FALSE)){ $data['url'] = $_POST['url']; }
              file_put_contents(self::hermes_file(), str_replace('\/', '/', json_encode($data)));
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
        $html = "Management module";
        //edit slaves.json = [ url, url ]
        //edit hermes.json = {"url": url, "key": key}
        //actions: upgrade, update, backup
        self::encapsule($html, TRUE);
        return FALSE;
    }
    public static function encapsule($content=NULL, $print=TRUE){
        //encapsule when an cache/empty.html skin is available

        if($print === TRUE){ print $content; exit; }
        return $content;
    }
    public static function run_slaves($action=NULL, $list=array()){ //herhaps the naming is politically incorrect; should be changed!
        if(!is_array($list) || count($list) == 0){
            if(!file_exists(self::slaves_file())){ return FALSE; }
            $list = json_decode(file_get_contents(self::slaves_file()), TRUE);
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
                $json[$url] = json_decode(file_get_contents(self::build_url($pu)), TRUE);
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
        $url .= ((isset($ar['query']) || isset($ar['fragment']) || isset($ar['path'])) ? (substr($ar['path'], 0, 1) != '/' ? '/' : NULL) : NULL);
        $url .= $ar['path'];
        $url .= (isset($ar['query']) ? '?'.$ar['query'] : NULL);
        $url .= (isset($ar['fragment']) ? '#'.$ar['fragment'] : NULL);
        return $url;
    }
    public static function hermes($path=FALSE){
        if(!file_exists(self::hermes_file())){ return FALSE; }
        if(!function_exists('curl_init') || !function_exists('curl_setopt') || !function_exists('curl_exec')){ return FALSE; }
        # $path + $url + $key
        $set = json_decode(file_get_contents(self::hermes_file()), TRUE);
        $url = (isset($set['url']) ? $set['url'] : self::hermes_default_remote());
        $key = (isset($set['key']) ? $set['key'] : FALSE);
        $message = array(
            "when"=>date('c'),
            "stamp"=>date('U'),
            "identity"=>substr(md5($_SERVER['REMOTE_ADDR']), 0, 24),
            "load"=>$path,
            "HTTP_USER_AGENT"=>$_SERVER['HTTP_USER_AGENT'],
            "REMOTE_ADDR"=>$_SERVER['REMOTE_ADDR'],
            "HTTP_ACCEPT_LANGUAGE"=>$_SERVER['HTTP_ACCEPT_LANGUAGE']
        );
        $message['item'] = $message['load'];
        $message = json_encode($message);
        if($key !== FALSE){ $message = self::encrypt($message, $key); }
        $message = 'json='.$message; //&var=
        $ch = curl_init( $url );
        curl_setopt( $ch, CURLOPT_POST, 1);
        curl_setopt( $ch, CURLOPT_POSTFIELDS, $message);
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt( $ch, CURLOPT_HEADER, 0);
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1);
        $response = curl_exec( $ch );
        return $response;
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
}
print_r($_SERVER);
/*fix*/ if(!isset($_GET['for'])){$_GET['for'] = NULL;}
\XLtrace\static_mirror::detect($_GET['for']);
?>
