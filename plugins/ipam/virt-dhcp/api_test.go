package main

import (
	"encoding/json"
	"testing"
)

func Test_autoConfLocalIPs(t *testing.T) {

	result := `{"annotations":null,"ips":[{"version":"4","address":"192.168.1.200/24","gateway":"192.168.1.1"}],"dns":{}}`
	var ack AcquireAck
	if err := json.Unmarshal([]byte(result), &ack); err != nil {
		t.Errorf("Error: %v", err)
	}
	t.Logf("Got %+v", ack)
}
