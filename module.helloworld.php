<?php
namespace XLtrace\Hades\module;
/********************************
 * This file is meant to be an example module you could create to work with static mirror.
 *
 * You can include this module by:
 *  define('HADES_MODULES', '\XLtrace\Hades\module\helloworld');
 *
 * Your module is not required to extend \XLtrace\module ,
 * but it can help you with inclusion of available methods trough $this->
 ********************************/
class helloworld extends \XLtrace\Hades\module {
    function get($for=NULL, &$set=array()){
        if($for == 'greeting'){ return 'Hello World!'; }
        return FALSE;
    }
}
?>
