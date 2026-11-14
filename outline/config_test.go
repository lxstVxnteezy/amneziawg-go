package outline

import "testing"

func TestConfigRejectsExtraUAPILines(t *testing.T) {
	for _, cfg := range []DeviceConfig{
		{H1: "1\nlisten_port=1"},
		{I1: "<b 0x01>\r\nlisten_port=1"},
		{Peers: []PeerConfig{{Endpoint: "127.0.0.1:1234\nreplace_peers=true"}}},
		{Peers: []PeerConfig{{AllowedIPs: []string{"0.0.0.0/0\nremove=true"}}}},
	} {
		if _, err := genIpcString(&cfg); err == nil {
			t.Fatal("accepted an extra UAPI command")
		}
	}
}
