mod_triger
========================================================================

Why repeat? There is a mod_substitute and mod_proxy_html.
------------------------------------------------------------------------
I don't want to parse the total response bodies and use regexes. I just
want insert my Javascript codes.

Introduction to  mod_triger?
------------------------------------------------------------------------
This module default action is just search <head> tag in the first data
bucket and search </body> tag in the last data bucket. If either tag
is found successfully, just insert JavaScript codes. If neither tag is
found, simply add the JavaScript codes to the end of the response
body.

The mod_triger assume following conditions
Tag '<head>' and '</body>' are not separated by space charaters, or
non-visible control charaters or new line. '<head>' tag should be one of
following formats
<head>
<head ...>

In a word, if responses produced by popular web containers, this module
will work well.

How to compile and install
------------------------------------------------------------------------

Following steps, except step 2, need run as root or sudo.

# 1. Install devel package

## For RHEL-like system
yum -y install httpd-devel gcc libtool

## For debian-like system, install one of apache develop package.
apt-get -y install apache2-prefork-dev gcc libtool
or
apt-get -y install apache2-threaded-dev gcc libtool

# 2. Get mod_triger source code
git clone https://github.com/xning/mod_triger.git

# 3. Complile and install

## For RHEL-like system
cd mod_triger
apxs -c mod_triger.c && apxs -i -a  mod_triger.la

## For debian-like system
cd mod_triger
apxs2 -c mod_triger.c && apxs2 -i -a  mod_triger.la

Configuraitons
------------------------------------------------------------------------

# Configurations work on RHEL6/Fedora
<VirtualHost *:80>
   ServerAdmin  admin@localhost.localdomain
   DocumentRoot /var/www/
   LogLevel        Debug
   TrigerEnable    On
   #TrigerInherit On
   #TrigerCheckLength 256
   #TrigerFullCheck On
   #TrigerContentType text/html application/xhtml+xml
   #TrigerHTML "<script>alert('Hello from mod_triger')</script>"
   ProxyPass        / http://www.redhat.com/
   ProxyPassReverse / http://www.redhat.com/
   ProxyRequests     Off
   SetOutputFilter  INFLATE;TRIGER;DEFLATE
</VirtualHost>
                                          

# All configuration directives of mod_tirger

The directives only work on main server or vhosts.

## TrigerEnable On/Off
Enable/Disable the Triger output filter.

## TrigerInherit On/Off
Inherit main server configurations or not. Only affect TrigerContentType, TrigerHTML, and TrigerCheckLength.

## TrigerFullCheck On/Off
Search each data bucket while no more than TrigerCheckLength, default is only check the first and last data buckets.

## TrigerContentType mime-types
Which types response that we will inject our HTML fragment, default are 'text/html' and 'application/xhtml+xml'.

## TrigerHTML HTMLfragment
HTML fragment that Triger will insert into responses bodies after <head> tag or before </body> tag,  or simple at the end if neither tags found.
Default is such string
"<script>alert('Hello from mod_triger')</script>"

## TrigerCheckLength number
How long contents we check to find tags so we know where to innsert our js coedes, f.g., <head> and </body>. Default is 256.


Notice
------------------------------------------------------------------------

If tag <head> is not in the first data bucket and </body> tag is not in
the last data bucket, or if the two tags are in two or more buckets,
mod_triger cannot find them, so cannot successfully process the response.
But this condition is nearly impossible.
