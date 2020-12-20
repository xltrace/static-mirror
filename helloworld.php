<?php
namespace XLtrace\hades\module;
/********************************
 * This file is meant to be an example module you could create to work with static mirror.
 * 
 * You can include this module by:
 *  define('HADES_MODULES', '\XLtrace\hades\module\helloworld');
 *
 * Your module is not required to extend \XLtrace\static_mirror ,
 * but it can help you with inclusion of available methods trough self::
 ********************************/
class helloworld extends \XLtrace\static_mirror {
    public static function detect($for=NULL){
        if($for == 'greeting'){ return 'Hello World!'; }
        return FALSE;
    }
}
?>
