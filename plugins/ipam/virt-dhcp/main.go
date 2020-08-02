package main

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	types020 "github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"

	log "github.com/sirupsen/logrus"
)

// Net The top-level network config - IPAM plugins are passed the full configuration
// of the calling plugin, not just the IPAM section.
type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	IPAM       *IPAMConfig `json:"ipam"`
}

type IPAMConfig struct {
	Name      string
	Type      string         `json:"type"`
	Server    string         `json:"server"`
	Routes    []*types.Route `json:"routes"`
	Addresses []Address      `json:"addresses,omitempty"`
	DNS       types.DNS      `json:"dns"`
}

type IPAMEnvArgs struct {
	types.CommonArgs
	IP      types.UnmarshallableString `json:"ip,omitempty"`
	GATEWAY types.UnmarshallableString `json:"gateway,omitempty"`
}

type Address struct {
	AddressStr string `json:"address"`
	Gateway    net.IP `json:"gateway,omitempty"`
	Address    net.IPNet
	Version    string
}

func init() {
	log.SetFormatter(&log.TextFormatter{})
	file, err := os.OpenFile("/tmp/virt-dhcp.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err == nil {
		log.SetOutput(file)
	} else {
		log.SetOutput(os.Stdout)
	}
	log.SetLevel(log.DebugLevel)
}

func main() {
	skel.PluginMain(cmdAdd, cmdCheck, cmdDel, version.All, "CNI virt-dhcp plugin v0.1")
}

func loadNetConf(bytes []byte) (*types.NetConf, string, error) {
	n := &types.NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, "", fmt.Errorf("failed to load netconf: %v", err)
	}
	return n, n.CNIVersion, nil
}

func cmdCheck(args *skel.CmdArgs) error {
	ipamConf, _, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Get PrevResult from stdin... store in RawPrevResult
	n, _, err := loadNetConf(args.StdinData)
	if err != nil {
		return err
	}

	// Parse previous result.
	if n.RawPrevResult == nil {
		return fmt.Errorf("Required prevResult missing")
	}

	if err := version.ParsePrevResult(n); err != nil {
		return err
	}

	result, err := current.NewResultFromResult(n.PrevResult)
	if err != nil {
		return err
	}

	// Each configured IP should be found in result.IPs
	for _, rangeset := range ipamConf.Addresses {
		for _, ips := range result.IPs {
			// Ensure values are what we expect
			if rangeset.Address.IP.Equal(ips.Address.IP) {
				if rangeset.Gateway == nil {
					break
				} else if rangeset.Gateway.Equal(ips.Gateway) {
					break
				}
				return fmt.Errorf("virt-dhcp: Failed to match addr %v on interface %v", ips.Address.IP, args.IfName)
			}
		}
	}

	return nil
}

// canonicalizeIP makes sure a provided ip is in standard form
func canonicalizeIP(ip *net.IP) error {
	if ip.To4() != nil {
		*ip = ip.To4()
		return nil
	} else if ip.To16() != nil {
		*ip = ip.To16()
		return nil
	}
	return fmt.Errorf("IP %s not v4 nor v6", *ip)
}

// LoadIPAMConfig creates IPAMConfig using json encoded configuration provided
// as `bytes`. At the moment values provided in envArgs are ignored so there
// is no possibility to overload the json configuration using envArgs
func LoadIPAMConfig(bytes []byte, envArgs string) (*IPAMConfig, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", err
	}

	if n.IPAM == nil {
		return nil, "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Validate all ranges
	numV4 := 0
	numV6 := 0

	for i := range n.IPAM.Addresses {
		ip, addr, err := net.ParseCIDR(n.IPAM.Addresses[i].AddressStr)
		if err != nil {
			return nil, "", fmt.Errorf("invalid CIDR %s: %s", n.IPAM.Addresses[i].AddressStr, err)
		}
		n.IPAM.Addresses[i].Address = *addr
		n.IPAM.Addresses[i].Address.IP = ip

		if err := canonicalizeIP(&n.IPAM.Addresses[i].Address.IP); err != nil {
			return nil, "", fmt.Errorf("invalid address %d: %s", i, err)
		}

		if n.IPAM.Addresses[i].Address.IP.To4() != nil {
			n.IPAM.Addresses[i].Version = "4"
			numV4++
		} else {
			n.IPAM.Addresses[i].Version = "6"
			numV6++
		}
	}

	if envArgs != "" {
		e := IPAMEnvArgs{}
		err := types.LoadArgs(envArgs, &e)
		if err != nil {
			return nil, "", err
		}

		if e.IP != "" {
			for _, item := range strings.Split(string(e.IP), ",") {
				ipstr := strings.TrimSpace(item)

				ip, subnet, err := net.ParseCIDR(ipstr)
				if err != nil {
					return nil, "", fmt.Errorf("invalid CIDR %s: %s", ipstr, err)
				}

				addr := Address{Address: net.IPNet{IP: ip, Mask: subnet.Mask}}
				if addr.Address.IP.To4() != nil {
					addr.Version = "4"
					numV4++
				} else {
					addr.Version = "6"
					numV6++
				}
				n.IPAM.Addresses = append(n.IPAM.Addresses, addr)
			}
		}

		if e.GATEWAY != "" {
			for _, item := range strings.Split(string(e.GATEWAY), ",") {
				gwip := net.ParseIP(strings.TrimSpace(item))
				if gwip == nil {
					return nil, "", fmt.Errorf("invalid gateway address: %s", item)
				}

				for i := range n.IPAM.Addresses {
					if n.IPAM.Addresses[i].Address.Contains(gwip) {
						n.IPAM.Addresses[i].Gateway = gwip
					}
				}
			}
		}
	}

	// CNI spec 0.2.0 and below supported only one v4 and v6 address
	if numV4 > 1 || numV6 > 1 {
		for _, v := range types020.SupportedVersions {
			if n.CNIVersion == v {
				return nil, "", fmt.Errorf("CNI version %v does not support more than 1 address per family", n.CNIVersion)
			}
		}
	}

	// Copy net name into IPAM so not to drag Net struct around
	n.IPAM.Name = n.Name

	return n.IPAM, n.CNIVersion, nil
}

func cmdAdd(args *skel.CmdArgs) error {

	ipamConf, confVersion, err := LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	log.Debugf("read cmdAdd.args ==> %s", args)
	k8sArgs := K8sArgs{}
	if err := types.LoadArgs(args.Args, &k8sArgs); err != nil {
		log.Errorf("read k8s args error %v", err)
		return err
	}

	ack, err := Acquire(ipamConf, args.ContainerID, string(k8sArgs.K8S_POD_NAMESPACE), string(k8sArgs.K8S_POD_NAME))
	if err != nil {
		log.Errorf("acquire ip error %v", err)
	}

	log.Infof("get ack %+v", ack)

	result := &current.Result{}
	result.DNS = ack.DNS
	result.Routes = ack.Routes
	result.IPs = ack.IPs
	if len(result.DNS.Nameservers) == 0 {
		result.DNS = ipamConf.DNS
	}
	if len(result.Routes) == 0 {
		result.Routes = ipamConf.Routes
	}
	if result.IPs[0].Gateway == nil {
		result.IPs = populateResultIPs(ack.IPs[0].Address.IP, ipamConf.Addresses)
	}
	log.Infof("cni ipam result %+v", result)

	return types.PrintResult(result, confVersion)
}

func populateResultIPs(ipv4 net.IP, addresses []Address) []*current.IPConfig {

	var ips []*current.IPConfig
	for _, v := range addresses {
		address := v.Address.IP
		if strings.Compare("4", v.Version) == 0 && !ipv4.IsUnspecified() {
			address = ipv4
		}
		log.Infof("version %s, use ip %s", v.Version, address.String())
		ips = append(ips, &current.IPConfig{
			Version: v.Version,
			Address: net.IPNet{
				IP:   address,
				Mask: v.Address.Mask,
			},
			Gateway: v.Gateway})
	}
	return ips
}

func cmdDel(args *skel.CmdArgs) error {
	log.Infof("Skip release ip %s, %s", args.Args, string(args.StdinData))
	return nil
}
