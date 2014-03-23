## About mod_triger

### Why repeat? There is a mod_substitute and mod_proxy_html.

I don't want to parse the total response bodies or use regexes. I just    
want insert my JavaScript codes after the &lt;head&gt; tag or before    
the &lt;/body&gt; tag simply. I found it was enough to scan the first    
data fragment (the first non-meta data bucket) of a response body.

### Introduction to  mod_triger?

This module default action is scan &lt;head&gt; tag in the first data     
bucket. If successful, insert HTML fragment after the &lt;head&gt;    
tag. If failed, scan &lt;/body&gt; tag in the last data bucket. If    
sucessful, insert HTML fragement before &lt;/body&gt. If failed,     
just insert JavaScript codes. If neither tag is to the end of the    
response body.

### The mod_triger assume following conditions
Tag &lt;head&gt; and &lt;/body&gt; are not separated by space charaters, or   
non-visible control charaters or new line. &lt;head&gt; tag should be one of   
following formats   
&lt;head&gt;   
&lt;head ...&gt;  

In a word, if responses produced by popular web containers, this module   
will work well.

### How to compile and install

Following steps, except step 2, need run as root or sudo.   

#### 1. Install devel package

##### For RHEL-like system
    yum -y install httpd-devel gcc libtool   

##### For debian-like system, install one of apache develop package.
    apt-get -y install apache2-prefork-dev gcc libtool   
or   
    apt-get -y install apache2-threaded-dev gcc libtool   

#### 2. Get mod_triger source code
    git clone https://github.com/xning/mod_triger.git   

#### 3. Complile and install

##### For RHEL-like system
    cd mod_triger   
    apxs -c mod_triger.c && apxs -i -a  mod_triger.la    

##### For debian-like system
    cd mod_triger
    apxs2 -c mod_triger.c && apxs2 -i -a  mod_triger.la

### Configuraitons

#### Configurations (Test on RHEL6)
    <VirtualHost *:80>
       ServerAdmin  admin@localhost.localdomain
       DocumentRoot /var/www/
       LogLevel       Debug
       TrigerEnable   On
       #TrigerInherit On
       #TrigerCheckLength 256
       #TrigerContentType text/html application/xhtml+xml
       #TrigerHTML "<script>alert('Hello from mod_triger')</script>"
       ProxyPass        / http://www.apache.org/
       ProxyPassReverse / http://www.apache.org/
       ProxyRequests     Off
       SetOutputFilter  INFLATE;TRIGER;DEFLATE
    </VirtualHost>
                                          

#### All configuration directives of mod_tirger

The following directives should appear in directive, locaitons, and .htaccess file .   

##### TrigerEnable On/Off
Enable/Disable the Triger output filter. Default is Off

##### TrigerInherit On/Off
Inherit main server configurations or not. Affect all others except itself. Default is On.

##### TrigerContentType mime-types
Which types response that we will inject our HTML fragment, default are 'text/html' and 'application/xhtml+xml'.

##### TrigerHTML HTMLfragment
HTML fragment that Triger will insert into responses bodies after &lt;head&gt; tag or before &lt;/body&gt; tag,  or simple at the end if neither tags found.   
Default is such string

    "<script>alert('Hello from mod_triger')</script>"

##### TrigerCheckLength number
How long contents we check to find tags so we know where to innsert our js coedes, f.g., &lt;head&gt; and &lt;/body&gt;. Default is 256.

### Notice

If tag &lt;head&gt; is not in the first data bucket and &lt;/body&gt; tag is not in   
the last data bucket, or if the two tags are in two or more buckets,   
mod_triger cannot find them, so cannot successfully process the response.   
But this condition is nearly impossible.   
