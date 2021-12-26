# kaminsky-attack

Kaminsky's cache poisoning attack on a resolver without source port randomization



## Environment 

The lab environment needs three separate machines, including

- victim's machine (192.168.10.10)
- attacker's machine (192.168.10.20)
- a DNS server (192.168.10.30)



## Result

Here are some snapshots. We can examine that the cache is indeed poisoned, map the hostname girls.hitcon.org to the fake IP address 1.2.3.4. 

![](https://raw.githubusercontent.com/chuang76/kaminsky-attack/main/figure/p1.PNG)

Actually, the entire domain hitcon.org is hijacked. The hostname cat.hitcon.org and dog.hitcon.org are redirected to the fake IP address 1.2.3.4. as well. 

![](https://raw.githubusercontent.com/chuang76/kaminsky-attack/main/figure/p2.PNG)

![](https://raw.githubusercontent.com/chuang76/kaminsky-attack/main/figure/p3.png)

