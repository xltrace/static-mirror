<?php
namespace XLtrace\Hades\module;
require_once(dirname(__DIR__).'/hades.php');
class maintenance extends \XLtrace\Hades\module {
  var $path = FALSE;
  var $patch = FALSE;
  function get($for=NULL, &$set=array()){
    switch(strtolower($for)){
      case 'initial': $str = $this->initial(); break;
      case 'configure': $str = $this->configure(); break;
      case 'duplicate': $str = $this->duplicate(); break;
      case 'upgrade': $str = $this->upgrade(); break;
      default:
        return FALSE;
    }
    /*cut short*/ if($str === FALSE){ return FALSE; } else { $this->for = $for; $this->set =& $set; }
    if($this->standalone === TRUE){
      if(is_array($set) && class_exists('\Morpheus')){ $morph = new \Morpheus(); $str = $morph->parse($str, $set); }
      //if($this->mode == "text/html" && function_exists('\Morpheus\markdown_decode')){ $str = \Morpheus\markdown_decode($str); }
    }
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
    \XLtrace\Hades\hermes('initial');
    if(strlen($path)>1 && !is_dir($path)){ mkdir($path); chmod($path, 00755); }
    if(strlen($patch)>1 && !is_dir($patch)){ mkdir($patch); chmod($patch, 00755); }
    if(!file_exists(__DIR__.'/.htaccess')){ file_put_contents(__DIR__.'/.htaccess', "RewriteEngine On\n\nRewriteCond %{HTTPS} !=on\nRewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\nRewriteRule \.(php)\$ - [L]\n\nRewriteRule ^\$ /static-mirror.php?for=index.html [QSA,L]\nRewriteRule ^(.*) /static-mirror.php?for=\$1 [QSA,L]"); }
    if(!file_exists(__DIR__.'/static-mirror.json')){ file_put_contents(__DIR__.'/static-mirror.json', \XLtrace\Hades\json_encode( (isset($_GET['src']) ? array($_GET['src']) : array()) )); }
    return TRUE;
  }
  public static function configure(){
    if(!file_exists(\XLtrace\Hades\hermes_file())){
      if(isset($_POST['token'])){
        $data = array('key'=>$_POST['token']);
        if(isset($_POST['url']) && (parse_url($_POST['url']) !== FALSE)){ $data['url'] = $_POST['url']; }
        file_put_contents(\XLtrace\Hades\hermes_file(), str_replace('\/', '/', \XLtrace\Hades\json_encode($data)));
        $this->initial();
        return $this->configure();
      }
      $html = '<form method="POST"><table><tr><td>Hermes remote:</td><td><input name="url" type="url" placeholder="'.\XLtrace\Hades\hermes_default_remote().'" value="'.\XLtrace\Hades\hermes_default_remote().'"/></td></tr><tr><td>Token:</td><td><input name="token" type="password"/></td></tr><tr><td colspan="2" align="right"><input type="submit" value="Configure" /></td></tr></table></form>';
      return $html;
      //\XLtrace\Hades\encapsule($html, NULL);
      //return FALSE;
    }
    $success = \XLtrace\Hades\authenticated(); // catch authenticated form data, so save token as cookie
    if($success !== TRUE){ return \XLtrace\Hades\signin(); }
    $html = "Configure Static-Mirror";
    //edit static-mirror.json = { page: src, page: src } | where page="index.html"
    //edit patch (before/after)
    //edit patch (preg/html-dom)
    return $thml;
    //\XLtrace\Hades\encapsule($html, NULL);
    //return FALSE;
  }
  function upgrade(){
    $raw = file_get_contents(\XLtrace\Hades\raw_git_path()."static-mirror.php");
    \XLtrace\Hades\hermes('upgrade');
    if(isset($_GET['all'])){ \XLtrace\Hades\run_slaves('upgrade'); }
    if(strlen($raw) > 10 && preg_match('#^[\<][\?]php\s#', $raw) && is_writable(__FILE__)){
      file_put_contents(__FILE__, $raw);
      foreach(array('.gitignore','README.md','composer.json','simple_html_dom.php') as $i=>$f){
        if(is_writable(__DIR__.'/'.$f)){ file_put_contents(__DIR__.'/'.$f, file_get_contents(\XLtrace\Hades\raw_git_path().$f)); }
      }
      $html = "Upgrade complete";
      return $html;
      //\XLtrace\Hades\encapsule($html, NULL);
      //return TRUE;
    }
    else {
      $html = "Upgrade failed, try again!";
      return $html;
      //\XLtrace\Hades\encapsule($html, NULL);
      //return FALSE;
    }
  }
  function backup(){
    \XLtrace\Hades\hermes('backup');
    if(isset($_GET['all'])){ \XLtrace\Hades\run_slaves('backup'); }
    return FALSE;
  }
  function duplicate(){
    $error = array();
    $success = \XLtrace\Hades\authenticated();
    if($success !== TRUE){ return \XLtrace\Hades\signin(); }
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
            @file_put_contents($map.basename(\XLtrace\Hades\hermes_file()), file_get_contents(\XLtrace\Hades\hermes_file()));
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
        $slaves = \XLtrace\Hades\file_get_json(\XLtrace\Hades\slaves_file(), TRUE, array());
        /*fix*/ if(!is_array($slaves)){ $slaves = array(); }
        if(!in_array($ns, $slaves)){
          if(\XLtrace\Hades\url_is_valid_status_json($ns)){
            $slaves[] = $ns;
            file_put_contents(\XLtrace\Hades\slaves_file(), \XLtrace\Hades\json_encode($slaves));
          } else { $error[] = $ns.' is not (yet) a valid static-mirror'; }
        }
        else { $error[] = $ns.' is already a slave'; }
      }
        else{ $error[] = $ns.' is not a valid url'; }
    }
    $debug = (FALSE ? print_r($_POST, TRUE).print_r($error, TRUE).print_r($notes, TRUE) : NULL);
    $html = $debug.'<form method="POST" action="duplicate"><table><tr><th colspan="2">'.$html.'</th></tr><tr><td>Path (on local server):</td><td><input name="path" placeholder="/domains/path/" /></td></tr><tr><td>Add as slave:</td><td><input type="url" name="slave" placeholder="https://" /></td></tr><tr><td><label><input type="checkbox" name="activate" value="true" checked="CHECKED"/> activate</label></td><td align="right"><input type="submit" value="Duplicate" /></td></tr></table>';
    return $html;
    //\XLtrace\Hades\encapsule($html, NULL);
    //return FALSE;
  }
}
?>
