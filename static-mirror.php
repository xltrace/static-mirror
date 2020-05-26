<?php
namespace XLtrace;
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);


$path = __DIR__.'/cache/';
$patch = __DIR__.'/patch/';

if(file_exists('simple_html_dom.php')){ require('simple_html_dom.php'); }

class static_mirror {
    var $path;
    var $patch;
    function __construct($path, $patch=FALSE){
        $this->path = $path;
        $this->patch = ($patch === FALSE ? $this->path : $patch);
    }
    public static function detect($for=NULL){
        switch(strtolower(preg_replace('#^[/]?(.*)$#', '\\1', $for))){
            case 'initial': self::initial(); self::hermes(); break;
            case 'backup': self::backup(); self::hermes(); break;
            case 'update': self::update(); self::hermes(); break;
            case 'upgrade': self::upgrade(); self::hermes(); break;
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
                    self::hermes();
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
            case 'php': header("HTTP/1.0 404 Not Found"); self::hermes(); return FALSE; break;
            case 'ppt': header('content-type: application/vnd.ms-powerpoint'); $hermes = TRUE; break;
            case 'pptx': header('content-type: application/vnd.openxmlformats-officedocument.presentationml.presentation'); $hermes = TRUE; break;
            case 'svg': header('content-type: image/svg+xml'); break;
            case 'ttf': header('content-type: font/ttf'); break;
            case 'txt': header('content-type: text/plain'); $hermes = TRUE; break;
            case 'woff': header('content-type: font/woff'); break;
            case 'woff2': header('content-type: font/woff2'); break;
            case 'xml': header('content-type: application/xml'); $hermes = TRUE; break;
            default: header("HTTP/1.0 404 Not Found"); self::hermes(); return FALSE;
        }


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
            file_put_contents(__DIR__.'/cache/'.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias), $raw);
            //file_put_contents(__DIR__.'/cache/'.$alias, $raw);
            print $raw;
        }
        if(!isset($hermes) || $hermes !== FALSE){ self::hermes(); }
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
        if(!file_exists(__DIR__.'/static-mirror.json')){ echo "No MIRROR configured."; return FALSE; }

        //$src = "https://platformvoorplaatselijkebelangen.nl/partijadministratie/";
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
        $raw = file_get_contents("https://raw.githubusercontent.com/xltrace/static-mirror/master/static-mirror.php");
        self::hermes();
        if(strlen($raw) > 10 && preg_match('#^[\<][\?]php\s#', $raw) && is_writable(__FILE__)){
            file_put_contents(__FILE__, $raw);
            file_put_contents(__DIR__.'/simple_html_dom.php', file_get_contents("https://raw.githubusercontent.com/xltrace/static-mirror/master/simple_html_dom.php"));
            print "Upgrade complete";
            return TRUE;
        }
        else {
            print "Upgrade failed, try again!";
            return FALSE;
        }
    }
    public static function backup(){
        self::hermes();
        return FALSE;
    }
    public static function hermes(){
        return TRUE;
    }
}


\XLtrace\static_mirror::detect($_GET['for']);
?>
