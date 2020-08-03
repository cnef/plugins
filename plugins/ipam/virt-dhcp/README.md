
```
[root@node2 net.d]# cat 10-bridge.conf
{
    "cniVersion": "0.2.0",
    "name": "mynet",
    "type": "bridge",
    "bridge": "br0",
    "isDefaultGateway": false,
    "forceAddress": false,
    "ipMasq": false,
    "hairpinMode": true,
    "ipam": {
        "type": "virt-dhcp",
        "server": "http://10.233.39.18/api/acquire",
        "ranges": [
            [{
                "subnet": "192.168.1.0/24",
                "rangeStart": "192.168.1.190",
                "rangeEnd": "192.168.1.220",
                "gateway": "192.168.1.1"
            }]
        ],
        "dns": {
            "nameservers": ["114.114.114.114", "61.139.2.69"]
        },
        "routes": [{
            "dst": "0.0.0.0/0"
        }]
    }
}
```