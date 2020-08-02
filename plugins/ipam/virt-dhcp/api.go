package main

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"time"

	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	log "github.com/sirupsen/logrus"
)

const resendDelay0 = 3 * time.Second
const resendDelayMax = 30 * time.Second
const resendCount = 3

var errNoMoreTries = errors.New("no more tries")

type CommonArgs struct {
	IgnoreUnknown types.UnmarshallableBool `json:"ignoreunknown,omitempty"`
}

type K8sArgs struct {
	types.CommonArgs
	IP net.IP
	// 不能用直接用字符串
	K8S_POD_NAME               types.UnmarshallableString
	K8S_POD_NAMESPACE          types.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID types.UnmarshallableString
}

type AcquireAck struct {
	Annotations map[string]string   `json:"annotations"`
	IPs         []*current.IPConfig `json:"ips,omitempty"`
	Routes      []*types.Route      `json:"routes,omitempty"`
	DNS         types.DNS           `json:"dns,omitempty"`
}

func Acquire(ipamConf *IPAMConfig, containerID, podNamespace, podName string) (*AcquireAck, error) {
	log.Infof("Acquire for pod: %s/%s, container: %s", podNamespace, podName, containerID)

	pkt, err := backoffRetry(func() (*AcquireAck, error) {
		client := http.Client{
			Timeout: 5 * time.Second,
		}
		acquireURL := fmt.Sprintf("%s?ns=%s&pod=%s&cid=%s", ipamConf.Server, podNamespace, podName, containerID)
		resp, err := client.Get(acquireURL)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, err := ioutil.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("Error resp: %s", string(body))
		}
		var ack AcquireAck
		if err = json.Unmarshal(body, &ack); err != nil {
			return nil, fmt.Errorf("Error Unmarshal: %v %s", err, string(body))
		}
		return &ack, nil
	})

	if err != nil || len(pkt.IPs) == 0 {
		log.Errorf("Acquire failed: %v", err)
		return &AcquireAck{
			IPs: autoConfLocalIPs(),
		}, nil
	}
	return pkt, nil
}

func randInt() int {
	b := []byte{0}
	rand.Reader.Read(b)
	return int(b[0])
}

func autoConfLocalIPs() []*current.IPConfig {
	log.Infof("Generate random auto config ip")

	randIP := fmt.Sprintf("169.254.%d.%d", randInt(), randInt())
	return []*current.IPConfig{{
		Version: "4",
		Address: net.IPNet{
			IP:   net.ParseIP(randIP),
			Mask: net.IPv4Mask(255, 255, 0, 0),
		},
		Gateway: net.ParseIP("169.254.0.1"),
	}}
}

func backoffRetry(f func() (*AcquireAck, error)) (*AcquireAck, error) {
	var baseDelay time.Duration = resendDelay0

	for i := 0; i < resendCount; i++ {
		pkt, err := f()
		if err == nil {
			return pkt, nil
		}

		log.Print(err)

		time.Sleep(baseDelay)

		if baseDelay < resendDelayMax {
			baseDelay *= 2
		}
	}

	return nil, errNoMoreTries
}
