<?php
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class static_mirror extends \XLtrace\Hades\module {
  var $path = FALSE;
  var $patch = FALSE;
  function get($for=NULL, &$set=array()){
    switch(strtolower($for)){
      //case 'update': $str = $this->update(); break;
      default:
        if(isset($for) && strlen($for) > 0){
            if(!$this->alias($for, TRUE)){
                $smdb = \XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array());
                if(isset($smdb[$for])){ $this->update($for); return TRUE; }
                $this->grab($for);
            }
            return TRUE;
        }
        else {
          $this->update();
          return TRUE;
        }
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
    if($this->mode == "text/html" && reset($el)!=='html' && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    return $str;
  }

  public function alias($path=NULL, $force=FALSE){
    /*fix*/ if($path === NULL){ $path = $_SERVER['REQUEST_URI']; }
    /*fix*/ if(substr($path, 0,1) == '/'){ $path = substr($path, 1); }

    $preg = '#^[\?]?(http[s]?|ftp)#';

    if(file_exists(\XLtrace\Hades\alias_file())){
      $db = \XLtrace\Hades\file_get_json(\XLtrace\Hades\alias_file(), TRUE, array());
    } else { return FALSE; }

    if(isset($db[strtolower($path)])){
      $path = (isset($db['#']) && preg_match($preg, $db['#']) ? $db['#'].(in_array(substr($db['#'], -1), array('/','=','?',':','#','~') ) ? NULL : '/'): NULL).$db[strtolower($path)];
    }

    if(preg_match($preg, $path)){ $url = substr($path, 1); }
    elseif(isset($db['*']) && preg_match($preg, $db['*'])){ $url = substr($db['*'], 1).(in_array(substr($db['*'], -1), array('/','=','?',':','#','~') ) ? NULL : '/').$path; }
    else{ return FALSE; }

    /*fix*/ if(preg_match("#^(.*)index\.html$#", $url, $buffer)){ $url = $buffer[1]; }

    if($force !== FALSE){
      if(!isset($hermes) || $hermes !== FALSE){ \XLtrace\Hades\hermes($path); }
      /*REDIRECTING*/
      header("HTTP/1.1 301 Moved Permanently");
      header("Location: ".$url);
      print '<html>You will be redirected to <a href="'.$url.'">'.$url.'</a>.</html>';
      exit;
    }
    return $url;
  }
  public function grab($for){
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
        case 'php': header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\hermes($for); return FALSE; break;
        case 'ppt': header('content-type: application/vnd.ms-powerpoint'); $hermes = TRUE; break;
        case 'pptx': header('content-type: application/vnd.openxmlformats-officedocument.presentationml.presentation'); $hermes = TRUE; break;
        case 'svg': header('content-type: image/svg+xml'); break;
        case 'ttf': header('content-type: font/ttf'); break;
        case 'txt': header('content-type: text/plain'); $hermes = TRUE; break;
        case 'woff': header('content-type: font/woff'); break;
        case 'woff2': header('content-type: font/woff2'); break;
        case 'xml': header('content-type: application/xml'); $hermes = TRUE; break;
        default: header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\hermes($for); \XLtrace\Hades\notfound($for); return FALSE;
    }

    if(!isset($hermes) || $hermes !== FALSE){ \XLtrace\Hades\hermes($for); }

    $G = $_GET; $P = $_POST; /*fix*/ if(isset($G['for'])){ unset($G['for']); } if(isset($P['raw']) && strlen($P['raw']) == 0){ unset($P['raw']); }
    if((function_exists('curl_init') && function_exists('curl_setopt') && function_exists('curl_exec')) && ((isset($G) && is_array($G) && count($G) > 0) || (isset($P) && is_array($P) && count($P) > 0))){
        //grab through CURL an uncached version, and do not cache
        $conf = \XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array());
        $src = reset($conf);
        if(strlen($src) < 6){ header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\notfound($for); return FALSE; }
        $url = parse_url($src, PHP_URL_SCHEME).'://'.parse_url($src, PHP_URL_HOST).'/'.$for;

        $url = $url.'?'.\XLtrace\Hades\array_urlencode($G);
        $ch = curl_init( $url );
        curl_setopt( $ch, CURLOPT_POST, 1);
        curl_setopt( $ch, CURLOPT_POSTFIELDS, \XLtrace\Hades\array_urlencode($P));
        curl_setopt( $ch, CURLOPT_FOLLOWLOCATION, 1);
        curl_setopt( $ch, CURLOPT_HEADER, 0);
        curl_setopt( $ch, CURLOPT_RETURNTRANSFER, 1);
        $raw = curl_exec( $ch );

        if(strlen($raw) == 0){ header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\notfound($for); return FALSE; }
        if($allow_patch !== FALSE){ $raw = \XLtrace\Hades\apply_patch($raw); }
        print \XLtrace\Hades\url_patch($raw, $allow_patch);
    }
    elseif(file_exists($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias))){
        print \XLtrace\Hades\url_patch(file_get_contents($path.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias)), $allow_patch);
    }
    elseif(file_exists($path.basename($for))){
        print \XLtrace\Hades\url_patch(file_get_contents($path.$alias), $allow_patch);
    }
    else {
        $conf = \XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array());
        $src = reset($conf);
        if(strlen($src) < 6){ header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\notfound($for); return FALSE; }
        $raw = file_get_contents(parse_url($src, PHP_URL_SCHEME).'://'.parse_url($src, PHP_URL_HOST).'/'.$for);
        if(strlen($raw) == 0){ header("HTTP/1.0 404 Not Found"); \XLtrace\Hades\notfound($for); return FALSE; }
        if($allow_patch !== FALSE){ $raw = \XLtrace\Hades\apply_patch($raw); }
        file_put_contents(__DIR__.'/cache/'.md5($for).'.'.preg_replace("#^(.*)[\.]([a-z0-9]+)$#", '\\2', $alias), $raw);
        //file_put_contents(__DIR__.'/cache/'.$alias, $raw);
        print \XLtrace\Hades\url_patch($raw, $allow_patch);
    }
    return TRUE;
  }
  function update($file='index.html'){
    if(!preg_match('#^[a-z0-9_\-]+\.html$#', $file)){ $file = 'index.html'; }
    if(isset($this)){
      $path = $this->path;
      $patch = $this->patch;
    }
    else {
      global $path, $patch;
    }

    \XLtrace\Hades\hermes('update');
    if(isset($_GET['all'])){ \XLtrace\Hades\run_slaves('update'); }

    if(!file_exists(__DIR__.'/static-mirror.json')){ echo "No MIRROR configured."; return FALSE; }

    $conf = \XLtrace\Hades\file_get_json(\XLtrace\Hades\static_mirror_file(), TRUE, array());
    if(isset($conf[$file])){ $src = $conf[$file]; }
    else{ $src = reset($conf); $file = 'index.html'; }

    if(!is_array($conf) || strlen($src) < 1){ echo "No MIRROR configured."; return FALSE; }

    if($file == 'index.html'){
    $list = scandir($path);
    foreach($list as $i=>$f){
      if(!preg_match('#^[\.]{1,2}$#', $f)){ unlink($path.$f); }
    }}

    $raw = file_get_contents($src);
    $raw = \XLtrace\Hades\apply_patch($raw);

    file_put_contents($path.$file, $raw);
    print \XLtrace\Hades\url_patch($raw);
    return $raw;
  }
}
?>
