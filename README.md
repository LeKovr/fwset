# fwset
Firewall set operations

```
$ ./fwset create
Blocklist created

$ ./fwset add 11.11.11.11
Network added

$ ./nft add 11.11.12.2/24
Network added

$ ./fwset add 11.11.13.2-11.11.13.16
Network added

$ ./fwset list
Blocked networks:
11.11.13.2-11.11.13.16
11.11.12.0/24
11.11.11.11

$ nft list ruleset
table ip myfirewall {
	set blocked_nets {
		type ipv4_addr
		flags interval
		elements = { 11.11.11.11, 11.11.12.0/24,
			     11.11.13.2-11.11.13.16 }
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr @blocked_nets counter packets 0 bytes 0 log drop
	}
}

$ ./fwset del 11.11.13.2-11.11.13.16
Network removed

$ ./fwset del 11.11.12.2/24
Network removed

$ ./fwset del 11.11.11.11
Network removed

$ ./fwset list
Blocked networks:

$ nft list ruleset
table ip myfirewall {
	set blocked_nets {
		type ipv4_addr
		flags interval
	}

	chain input {
		type filter hook input priority filter; policy accept;
		ip saddr @blocked_nets counter packets 0 bytes 0 log drop
	}
}
```
