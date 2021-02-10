<?php
/******************
<?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="//localhost/sitemap.xsl"?>
<urlset xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1" xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd http://www.google.com/schemas/sitemap-image/1.1 http://www.google.com/schemas/sitemap-image/1.1/sitemap-image.xsd" xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
	<url>
		<loc>https://localhost/path/</loc>
		<lastmod>2013-08-14T17:34:13+00:00</lastmod>
		<image:image>
			<image:loc>https://localhost/image.png</image:loc>
			<image:title><![CDATA[Image description]]></image:title>
		</image:image>
	</url>
</urlset>

[
  {"loc":"https://localhost/path/","lastmod":29391399,
    "images":[ {"loc":"https://localhost/image.png","title":"Image description"} ]
  }
]
*****************/
namespace XLtrace\Hades\module;
require_once(__DIR__.'/static-mirror.php');
class sitemap extends \XLtrace\Hades\module {
  var $standalone = TRUE;
  function get($for=NULL, &$set=array()){
    $str = FALSE;
    switch(strtolower($for)){
      case 'robots.txt': $str = $this->robots_txt($set); break;
      case 'sitemap.xml': $str = $this->sitemap_xml($set); break;
      case 'sitemap-all.xml': $str = $this->sitemap_index_xml($set); break;
      case 'sitemap.xsl': $str = $this->sitemap_xsl($set); break;
      case 'sitemap.json': $str = $this->sitemap_json($set); break;
      case 'sitemap': case 'sitemap.html': $str = $this->sitemap_html($set); break;
      default:
        return FALSE;
    }
    $this->for = $for;
    if($this->standalone === TRUE){ header('Content-type: '.$this->mode); }
    return $str;
  }
  function robots_txt(){
    $this->mode = 'text/plain';
    /*override*/ if(file_exists('robots.txt')){ return file_get_contents('robots.txt'); }
    /* Disallow: /secret/  \n  Allow: /secret/not-anymore.php */
    return "User-agent: *\nSitemap: ".\XLtrace\Hades\current_URI('sitemap.xml');
  }
  function collect_sitemaps($module=FALSE, $settings=array()){
    $json = array();
    /*This script should crawl all available modules*/
    return $json;
  }
  function sitemap_index_xml($json=FALSE){
    if($json === FALSE){ $json = $this->collect_sitemaps(); }
    /*hack*/ $this->mapper = FALSE; $json = array(\XLtrace\Hades\current_URI('sitemap.xml'), $this->get_sitemap_URI() );
    $this->mode = 'application/xml';
    $xmlstr  = '<?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="'.\XLtrace\Hades\current_URI('sitemap.xsl').'"?>'."\n";
    $xmlstr .= '<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'."\n";
    foreach($json as $i=>$url){if(!is_bool($url)){
      $xmlstr .= "\t<sitemap>\n";
      $xmlstr .= "\t\t<loc>".(is_array($url) ? $url['loc'] : $url)."</loc>\n";
      if(isset($url['lastmod'])){ $xmlstr .= "\t\t<lastmod>".(is_int($url['lastmod']) ? date('c', $url['lastmod']) : $url['lastmod'])."</lastmod>\n"; }
      $xmlstr .= "\t</sitemap>\n";
    }}
    $xmlstr .= '</sitemapindex>';
    return $xmlstr;
  }
  function sitemap_xml($json=FALSE){
    if($json === FALSE){ $json = $this->collect_sitemaps(); }
    //*debug*/ print '<!-- '; var_dump($json); print ' -->';
    $this->mode = 'application/xml';
    $xmlstr  = '<?xml version="1.0" encoding="UTF-8"?><?xml-stylesheet type="text/xsl" href="'.\XLtrace\Hades\current_URI('sitemap.xsl').'"?>'."\n";
    $xmlstr .= '<urlset xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:image="http://www.google.com/schemas/sitemap-image/1.1" xsi:schemaLocation="http://www.sitemaps.org/schemas/sitemap/0.9 http://www.sitemaps.org/schemas/sitemap/0.9/sitemap.xsd http://www.google.com/schemas/sitemap-image/1.1 http://www.google.com/schemas/sitemap-image/1.1/sitemap-image.xsd" xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'."\n";
    foreach($json as $i=>$url){
      $xmlstr .= "\t<url>\n";
      foreach(array('loc','lastmod','changefreq','priority','images') as $attr){
        switch($attr){
          case 'images':
            break;
          default:
            if(isset($url[$attr])){
              /*fix*/ if($attr == 'lastmod' && is_int($url[$attr])){ $url[$attr] = date('c', $url[$attr]); }
              $xmlstr .= "\t\t<".$attr.">".$url[$attr]."</".$attr.">\n";
            }
        }
      }
      $xmlstr .= "\t</url>\n";
    }
    $xmlstr .= '</urlset>';
    return $xmlstr;
  }
  function sitemap_json($json=FALSE){
    if($json === FALSE){ $json = $this->collect_sitemaps(); }
    $str = NULL;
    if(is_array($json)){ $str = \XLtrace\Hades\json_encode($json); }
    $this->mode = 'application/json';
    return $str;
  }
  function sitemap_html($json=FALSE){
    if($json === FALSE){ $json = $this->collect_sitemaps(); }
    $this->mode = 'text/html';
    return NULL;
  }
  public static function sitemap_xsl(){
    //$this->mode = 'text/xsl';
    return '<?xml version="1.0" encoding="UTF-8"?>
	<xsl:stylesheet version="2.0"
		xmlns:html="http://www.w3.org/TR/REC-html40"
		xmlns:image="http://www.google.com/schemas/sitemap-image/1.1"
		xmlns:sitemap="http://www.sitemaps.org/schemas/sitemap/0.9"
		xmlns:xsl="http://www.w3.org/1999/XSL/Transform">
	<xsl:output method="html" version="1.0" encoding="UTF-8" indent="yes"/>
	<xsl:template match="/">
		<html xmlns="http://www.w3.org/1999/xhtml">
		<head>
			<title>XML Sitemap</title>
			<meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
			<style type="text/css">
				body {
					font-family: Helvetica, Arial, sans-serif;
					font-size: 13px;
					color: #545353;
				}
				table {
          width: 100%;
          max-width: 800px;
					border: none;
					border-collapse: collapse;
				}
				#sitemap tr:nth-child(odd) td {
					background-color: #eee !important;
				}
				#sitemap tbody tr:hover td {
					background-color: #ccc;
				}
				#sitemap tbody tr:hover td, #sitemap tbody tr:hover td a {
					color: #000;
				}
				#content {
					margin: 0 auto;
					width: 1000px;
				}
				.expl {
					margin: 18px 3px;
					line-height: 1.2em;
				}
				.expl a {
					color: #da3114;
					font-weight: 600;
				}
				.expl a:visited {
					color: #da3114;
				}
				a {
					color: #000;
					text-decoration: none;
				}
				a:visited {
					color: #777;
				}
				a:hover {
					text-decoration: underline;
				}
				td {
					font-size:11px;
				}
				th {
					text-align:left;
					padding-right:30px;
					font-size:11px;
				}
				thead th {
					border-bottom: 1px solid #000;
				}
			</style>
		</head>
		<body>
		<div id="content">
			<h1>XML Sitemap</h1>
			<p class="expl">
				Generated by <a href="'.\XLtrace\Hades\current_URI('/').'" target="_blank" rel="noopener noreferrer">Hades</a> its <a href="'.\XLtrace\Hades\current_URI('seo/').'" target="_blank" rel="noopener noreferrer">Search Engine Optimalisation</a>, this is an XML Sitemap, meant for consumption by search engines.<br/>
				You can find more information about XML sitemaps on <a href="http://sitemaps.org" target="_blank" rel="noopener noreferrer">sitemaps.org</a>.
			</p>
			<xsl:if test="count(sitemap:sitemapindex/sitemap:sitemap) &gt; 0">
				<p class="expl">
					This XML Sitemap Index file contains <xsl:value-of select="count(sitemap:sitemapindex/sitemap:sitemap)"/> sitemaps.
				</p>
				<table id="sitemap" cellpadding="3">
					<thead>
					<tr>
						<th width="75%">Sitemap</th>
						<th width="25%">Last Modified</th>
					</tr>
					</thead>
					<tbody>
					<xsl:for-each select="sitemap:sitemapindex/sitemap:sitemap">
						<xsl:variable name="sitemapURL">
							<xsl:value-of select="sitemap:loc"/>
						</xsl:variable>
						<tr>
							<td>
								<a href="{$sitemapURL}"><xsl:value-of select="sitemap:loc"/></a>
							</td>
							<td>
								<xsl:value-of select="concat(substring(sitemap:lastmod,0,11),concat(\' \', substring(sitemap:lastmod,12,5)),concat(\' \', substring(sitemap:lastmod,20,6)))"/>
							</td>
						</tr>
					</xsl:for-each>
					</tbody>
				</table>
			</xsl:if>
			<xsl:if test="count(sitemap:sitemapindex/sitemap:sitemap) &lt; 1">
				<p class="expl">
					This XML Sitemap contains <xsl:value-of select="count(sitemap:urlset/sitemap:url)"/> URLs.
				</p>
				<table id="sitemap" cellpadding="3">
					<thead>
					<tr>
						<th width="70%">URL</th>
						<th width="5%">Images</th>
						<th title="Last Modification Time" width="15%">Last Mod.</th>
						<th width="5%">Priority</th>
						<th width="5%">Frequency</th>
					</tr>
					</thead>
					<tbody>
					<xsl:variable name="lower" select="\'abcdefghijklmnopqrstuvwxyz\'"/>
					<xsl:variable name="upper" select="\'ABCDEFGHIJKLMNOPQRSTUVWXYZ\'"/>
					<xsl:for-each select="sitemap:urlset/sitemap:url">
						<tr>
							<td>
								<xsl:variable name="itemURL">
									<xsl:value-of select="sitemap:loc"/>
								</xsl:variable>
								<a href="{$itemURL}">
									<xsl:value-of select="sitemap:loc"/>
								</a>
							</td>
							<td>
								<xsl:value-of select="count(image:image)"/>
							</td>
							<td>
								<xsl:value-of select="concat(substring(sitemap:lastmod,0,11),concat(\' \', substring(sitemap:lastmod,12,5)),concat(\' \', substring(sitemap:lastmod,20,6)))"/>
							</td>
							<td>
								<xsl:value-of select="sitemap:priority"/>
							</td>
							<td>
								<xsl:value-of select="sitemap:changefreq"/>
							</td>
						</tr>
					</xsl:for-each>
					</tbody>
				</table>
			</xsl:if>
		</div>
		</body>
		</html>
	</xsl:template>
</xsl:stylesheet>';
  }
}
?>
