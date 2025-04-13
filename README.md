# fwset
Firewall set operations

Firewalls supported
* [x] nftables
* [ ] ipset

```
$ nft list ruleset
table inet filter {
    chain input {
	type filter hook input priority filter; policy accept;
    }

    chain forward {
	type filter hook forward priority filter; policy accept;
    }

    chain output {
	type filter hook output priority filter; policy accept;
    }
}

$ ./fwset create
fwset v0.3.0
Sets created

$ ./fwset --accept add 10.10.10.0/24
fwset v0.3.0
Network added

$ ./fwset add 11.11.13.2-11.11.13.16 11.11.12.2/24 11.11.11.11
fwset v0.3.0
Network added

$ nft list table myfirewall
table ip myfirewall {
    set allowed_nets {
	type ipv4_addr
	flags interval
	elements = { 10.10.10.0/24 }
    }

    set blocked_nets {
	type ipv4_addr
	flags interval
	elements = { 11.11.11.11, 11.11.12.0/24,
	         11.11.13.2-11.11.13.16 }
    }

    chain input {
	type filter hook input priority filter; policy accept;
	ip saddr @allowed_nets counter packets 0 bytes 0 log accept
	ip saddr @blocked_nets counter packets 0 bytes 0 log drop
    }
}

$ ./fwset del 11.11.13.2-11.11.13.16
fwset v0.3.0
Network removed

$ nft list table myfirewall
table ip myfirewall {
    set allowed_nets {
	type ipv4_addr
	flags interval
	elements = { 10.10.10.0/24 }
    }

    set blocked_nets {
	type ipv4_addr
	flags interval
	elements = { 11.11.11.11, 11.11.12.0/24 }
    }

    chain input {
	type filter hook input priority filter; policy accept;
	ip saddr @allowed_nets counter packets 0 bytes 0 log accept
	ip saddr @blocked_nets counter packets 0 bytes 0 log drop
    }
}

$ ./fwset destroy
fwset v0.3.0
Sets destroyed

$ nft list ruleset
table inet filter {
    chain input {
	type filter hook input priority filter; policy accept;
    }

    chain forward {
	type filter hook forward priority filter; policy accept;
    }

    chain output {
	type filter hook output priority filter; policy accept;
    }
}
```
