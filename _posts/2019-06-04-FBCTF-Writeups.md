---
layout: post
current: post
cover: assets/images/fbctf.png
navigation: True
title: facebook ctf writeups
date: 2019-06-04 17:07:00 +0530
tags: facebook ctf writeups security
class: post-template
subclass: post
toc: True
disqus: True
---
This is the first facebook ctf. I participated with [InfoSecIITR](https://infoseciitr.github.io/) and solved 2 challenges. This post contains the writeups for solved challenges and my ideas about the ones I didn't solve but could have.

### products manager - web
This challenge is written by one of our alumini, [@vampire](https://twitter.com/dhaval_kapil). The source code shows use of PDO which crosses out query based injection. But then I noticed the schema which had a maximum capacity for all the fields and looked at my [web exploitation notes](https://github.com/rnehra01/web-cheats/blob/master/sqli.md#common-errs) which gave me the idea of inserting a duplicate _facebook_ product with my secret. So I used `facebook + ' '*56 + hack` as name, `not_so_secret` as secret and `hacked!!!` as description and the product was successfully inserted. And I could now view the product using `facebook` and `not_so_secret` and got the flag.
Basically SQL ignored all characters after the length 64 and truncates the whitespaces by default.

### homework_assignment_1337 - misc
This challenge is based on based on a RPC protocol, thrift. The task is to write a thrift client. So I installed thrift and got a thrift client working using the documentation.
{% highlight python %}
from ping import PingBot
from ping.ttypes import *

from thrift import Thrift
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

try:

  # Make socket
  transport = TSocket.TSocket('challenges.fbctf.com', 9090)

  # Buffering is critical. Raw sockets are very slow
  transport = TTransport.TBufferedTransport(transport)

  # Wrap in a protocol
  protocol = TBinaryProtocol.TBinaryProtocol(transport)

  # Create a client to use the protocol encoder
  client = PingBot.Client(protocol)

  # Connect!
  transport.open()
  out = client.ping(Ping(1, 'facebook.com:80', 'Hi There!'))
  print(out)

  # Close!
  transport.close()

except Thrift.TException, tx:
  print 'Error: %s' % (tx.message)
{% endhighlight %}

I pinged facebook.com and got a pong back `Pong(code=0, data='HTTP/1.1 400 Bad Request\r\n')`.
And if I used `pingdebug` then I got `Internal error processing pingdebug: DO_NOT_USE pingdebug() reserved for local inspections` as the challenge file said that you could use the `pingdebug` method only through localhost.
Initially I was trying to find vulns in the thrift protocol itself but no luck. But later I noticed that the `ping` method setup a TCP connection and send data through that connect so I could smuggle data related to thrift protocol that would invoke the `pingdebug` method. Now I need to find data to send to `127.0.0.1:9090` to call `pingdebug`. Instead reading about protocol to get the data, I captured a packet which was calling `pingdebug` through wireshark.

<img src="/assets/images/pingdebug.png" alt="pingdebug Packet">

I used the highlighted thrift data and made the pingdebug call and got the flag in response.
{% highlight python %}
data = ('800100010000000970696e676465627567000000000c0001080001000005390000').decode('hex')
out = client.ping(Ping(1, '127.0.0.1:9090', data))
{% endhighlight %}

### osquery_game - misc
I couldn't solve this challenge during the ctf. We needed to complete some quests to get the flag using osquery which is basically SQLite.
<pre>
osquery> select * from farm_quests;
from      |message|done
Town Mayor|<mark>The sheep wants to be next to the pig. Please move him, but be careful, if he sees you he will run away in less than a second, you need to move fast.</mark>|yes
Town Mayor|<mark>Please water something that you have planted. You need to pickup a pail first. The sheep was playing with the water pail, if you move him next to his friend he may give it back.</mark>|no
Town Mayor|<mark>Please pick something that you have grown. Wait a day after planting a seed and watering then pickup your plants.</mark>|yes
Town Mayor|<mark>Weeds grow the first day of each season. Be careful, seeds and small plants will be overtaken.</mark>|no
</pre>
Basically you needed to do 5 tasks:
1. Keep sheep next to pig
2. Plant a seed
3. Pickup water
4. Water the planted seed
5. Pickup your plant

Now you need to quickly keep the pig alongside the sheep as soon as you access farm for the first time otherwise the sheep would run away and the quest would fail.
So I wrote a SQL query for that
{% highlight sql %}
select farm from farm where action='move' and src=
(select(((pigt-36)-pigV*18)+ pigV*16-1) from
(select instr(farm, '🐷') as pigt, (instr(farm, '🐷')-36)/18 as pigV from farm)) and dst=
(select(((pigt-36)-pigV*18)+ pigV*16)
from (select instr(farm, '🐑') as pigt, (instr(farm, '🐑')-36)/18 as pigV from farm));

farm
  0 1 2 3 4 5 6 7 8 9 A B C D E F 
0🌿🌿🚜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
1🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
2🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
3🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
4🌿🌿⬜🌿🐑🐷🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
5🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
6🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
7🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
8🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
9🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
A🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌻🌿🌿
B🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
C🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
D🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
E🌿🌿⬜🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
F🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿🌿
{% endhighlight %}
This did the job but used 4 farming days and we had to complete all the quests in 5 days. Also I needed to coordinates of emojis while performing a certain task so I needed to access the farm twice to complete every quest which would be 10 days.

Now since the plowing area was a long vertical column so seed planting could be done by brute-forcing the coordinates as only horizontal coordinate needed to be guessed, the other could be set from 1 to E which reduced one access to farm in this quest. Bit still it wouldn't help to solve the challenge.

After sometime I got an idea of copying the initial farm table to a temporary one and use that to get coordinates of emojis and this worked. As I could do all tasks in 1 farm access plus 1 access of copying so it resulted in 6 days, I needed to cut by 1 days.
{% highlight sql %}
create table tmp(farm TEXT, action TEXT, src INTEGER, dst INTEGER);
insert into tmp select * from farm;
select farm from farm where action='move' and src=
(select(((pigt-36)-pigV*18)+ pigV*16-1) from
(select instr(farm, '🐷') as pigt, (instr(farm, '🐷')-36)/18 as pigV from tmp)) and dst=
(select(((pigt-36)-pigV*18)+ pigV*16)
from (select instr(farm, '🐑') as pigt, (instr(farm, '🐑')-36)/18 as pigV from tmp));
{% endhighlight %}

Later I used the below query to perform sheep-pig quest but I couldn't remove the error `Invalid move. The src column must contain one value`. 
{% highlight sql %}
select farm as pig from farm where action='move' and src=
((instr(farm, '🐷')-36)-(((instr(farm, '🐷')-36)/18)*18)+(((instr(farm, '🐷')-36)/18)*16)-1)
and dst=
((instr(farm, '🐑')-36)-(((instr(farm, '🐑')-36)/18)*18)+(((instr(farm, '🐑')-36)/18)*16));
{% endhighlight %}
I guess the `farm` used in `src` was returning a column not a single value.

Later after looking at a writeup I noticed that I missed a simple trick, I could complete seed-planting quest by bruteforcing and also copy the table side by side.
{% highlight sql %}
create table tmp(farm TEXT, action TEXT, src INTEGER, dst INTEGER);
insert into tmp select * from farm where action='plant' and dst=0x22;
{% endhighlight %}
Now I had 4 remaining days, 4 quests and a temporary table to get coordinates so it could have been done.
