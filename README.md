## About mod_triger

### Why repeat? There is a mod\_substitute and mod\_proxy\_html.

I don't want to parse the total response bodies or use regexes. I just    
want insert my JavaScript codes after the &lt;head&gt; tag or before    
the &lt;/body&gt; tag simply. I found it was enough to scan the first    
data fragment (the first non-meta data bucket) of a response body.

### Introduction to mod\_triger?

This module default action is scan &lt;head&gt; tag in the first data     
bucket. If successful, insert HTML fragment after the &lt;head&gt;    
tag. If failed, scan &lt;/body&gt; tag in the last data bucket. If    
sucessful, insert HTML fragement before &lt;/body&gt;. If failed,     
just insert JavaScript codes to the end of the response body.

### The mod\_triger assume following conditions
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

#### 2. Get mod\_triger source code
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
mod\_triger cannot find them, so cannot successfully find tags in the response.   
But this condition is nearly impossible.   

Even in the worst situation, mod\_triger doesn't just skip the response, it will add    
the HTML fragments at the end of the response body. Believe it or not, this work    
well for mainstream browsers.  

### How to configure mod_proxy for https and Kerberos authentication

#### 1. Create a self-signed certificate

        openssl genrsa -out server.key 1024  
        openssl req -new -key server.key -out server.csr  
        cp server.key server.key.org  
        openssl rsa -in server.key.org -out server.key  
        openssl x509 -req -days 365 -in server.csr -signkey server.key -out server.crt  

Then copy the public and private certificates to the right path

        cp server.crt /etc/pki/tls/certs/server.crt  
        cp server.key /etc/pki/tls/private/server.key  

#### 2. Tips

To make sure that the Kerberos authentication could work, we need the user engent, here it is firefox,
to access our proxy server by the orgin backend server DNS name. Hence we should configure the /etc/hosts for firefox.

For example, suppose we have two hosts. One is 192.168.0.3, the other is 192.168.0.7. We run Firefox
on the former host, and Apache HTTPD (the proxy host) on the later one. And we let the later to proxy the backend web server "projects.example.com".

So we add the following line to the /etc/hosts file on the 192.168.0.3  

         192.168.0.7 projects.example.com

Sure here you need configure firefox to support the Kerberos authentication. Pls reference  

[Configuring Firefox to use Kerberos for SSO](https://access.redhat.com/documentation/en-US/Red_Hat_Enterprise_Linux/5/html/Deployment_Guide/sso-config-firefox.html)

#### 3. Configuring mod_proxy

Here is an example.  

     <VirtualHost 192.168.0.7:443>  
          ServerName projects.example.com  

          ErrorLog logs/ssl_error_log  
          TransferLog logs/ssl_access_log  
          LogLevel Warn  
           
          SSLEngine on  
          
          SSLProtocol all -SSLv2  
          SSLCipherSuite ALL:!ADH:!EXPORT:!SSLv2:RC4+RSA:+HIGH:+MEDIUM:+LOW  
          
          SSLCertificateFile /etc/pki/tls/certs/server.crt  
          SSLCertificateKeyFile /etc/pki/tls/private/server.key  
          
          <Files ~ "\.(cgi|shtml|phtml|php3?)$">  
              SSLOptions +StdEnvVars  
          </Files>  
          <Directory "/var/www/cgi-bin"&gt  
              SSLOptions +StdEnvVars  
          </Directory>  
          
          SetEnvIf User-Agent ".*MSIE.*" \  
              nokeepalive ssl-unclean-shutdown \  
              downgrade-1.0 force-response-1.0  
          
          CustomLog logs/ssl_request_log \  
               "%t %h %{SSL_PROTOCOL}x %{SSL_CIPHER}x \"%r\" %b"  
          
          ServerAdmin  admin@localhost.localdomain  
          DocumentRoot /var/www/  
          TrigerEnable   On  
          #TrigerInherit On  
          #TrigerCheckLength 256  
          #TrigerContentType text/html application/xhtml+xml  
          #TrigerHTML '<script type="text/javascript" defer>console.log("Hello from mod_triger")</script>'  
          SSLProxyEngine On  
          ProxyPassInterpolateEnv On  
          AllowCONNECT 443  
          # The backend server's CA certificate if the CA is not a public one.
          SSLProxyCACertificateFile /etc/pki/tls/certs/backend_server.crt  
          ProxyPassMatch        ^/znznzs/.*\.js$ !  
          ProxyPass        / https://projects.example.com/  
          ProxyPassReverse / https://projects.example.com/  
          
          ProxyRequests     Off  
          ProxyPreserveHost On  
          SetOutputFilter  INFLATE;TRIGER;DEFLATE  
    </VirtualHost>

#### 4. It's time to try.

First, tell the Apache HTTPD to read the above configuration.

        service httpd restart

Second, get a TGT

        kinit

It's time to try now.

### How to run more than one proxy on a single server?

If we need run more than one proxy on a single server, we face the following
questions.

#### 1. Wildcard certificate or multiple certificates.

I think it's possible to use a wildcard certificate, while I just simply tried this solution, and it seems that we need add each proxied servers DNS names to the extend fields of the wildcard certificate.

#### 2. Multiple IPs or multiple port.

We prefer the former solution.

### Persistent storage for our JavaScript

We can try one of the following ways.

##### 1. Proxy server-side database

We can setup a mysql/postgresql server on the proxy server-side. Then we use
[mod\_perl](https://perl.apache.org/) or [mod\_php](http://php.net/) to
create CGI scripts or something. After that our JavaScript could read and
write the server-side database.

Sure we can simply just use one of the database that completely embraces the
web. For example, [couchdb](http://couchdb.apache.org/) or
[riak](http://basho.com/riak/).

##### 2. HTML5 client-side Storage and filesystem API

Firefox don't support the filesystem API now. Pls reference the following links

[Why no FileSystem API in Firefox?](https://hacks.mozilla.org/2012/07/why-no-filesystem-api-in-firefox/)  [WebAPI/FileHandleAPI](https://wiki.mozilla.org/WebAPI/FileHandleAPI)  
[LocalFileSystem](https://developer.mozilla.org/zh-CN/docs/Web/API/LocalFileSystem)

And the indxedDB stores data, except the search key, is binary blob. I don't
know tools or how to parse these blobs.

So, now, we can use the [loaclStorage/sessionStorage](https://developer.mozilla.org/en-US/docs/Web/Guide/API/DOM/Storage),
perhaps cookies and caches  

The data stored in [localStorage/sessionStorage](https://developer.mozilla.org/en-US/docs/Web/Guide/API/DOM/Storage) is in a SQLite database. And we can easily have these data to
be JSON format.

To run Firefox from the command-line, pls reference [Firefox\-as\-daemon](https://github.com/xning/bash-functions-for-firefox).

#### 3. Directly read/write the backend server storage.

Yes, it's possible, while I didn't ever encounter one. 

### Firefox need an X server

Pls reference [Firefox\-as\-daemon](https://github.com/xning/bash-functions-for-firefox).

### Wireshark and HTTPS

Pls reference here

[NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)

### Backend server perhaps have two DNS names.

Sometimes some server have two DNS names, and the Kerberos authentication will fail because of this.
You can catch the HTTPS packets to verify what happens. 
