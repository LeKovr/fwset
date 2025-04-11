package utils

import (
	"net"
	"reflect"
	"testing"

	ass "github.com/alecthomas/assert/v2"
)

func TestParseNetwork(t *testing.T) {
	tests := []struct {
		input    string
		expected string
		wantErr  bool
	}{
		{"192.168.1.1", "192.168.1.1/32", false},
		{"10.0.0.0/24", "10.0.0.0/24", false},
		{"invalid", "", true},
		{"2001:db8::/32", "2001:db8::/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ipnet, err := ParseNetwork(tt.input)
			if tt.wantErr {
				ass.Error(t, err)
				return
			}
			ass.NoError(t, err)
			ass.Equal(t, tt.expected, ipnet.String())
		})
	}
}

func TestCIDRToRange(t *testing.T) {
	tests := []struct {
		input  string
		start  string
		end    string
		isIPv6 bool
	}{
		// IPv4
		{"192.168.1.1", "192.168.1.1", "192.168.1.1", false},
		{"192.168.1.1/32", "192.168.1.1", "192.168.1.1", false},
		{"10.0.0.0/24", "10.0.0.0", "10.0.0.255", false},
		{"172.16.0.0/16", "172.16.0.0", "172.16.255.255", false},

		// IPv6
		{"2001:db8::/32", "2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"fd00::/8", "fd00::", "fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			start, end, err := CIDRToRange(tt.input)
			ass.NoError(t, err)
			// Проверка IPv4
			if !tt.isIPv6 {
				if start.String() != tt.start || end.String() != tt.end {
					t.Errorf("Expected %s-%s, got %s-%s",
						tt.start, tt.end, start, end)
				}
				return
			}

			// Проверка IPv6
			expectedStart := net.ParseIP(tt.start)
			expectedEnd := net.ParseIP(tt.end)
			if !start.Equal(expectedStart) || !end.Equal(expectedEnd) {
				t.Errorf("Expected %s-%s, got %s-%s",
					expectedStart, expectedEnd, start, end)
			}
		})
	}
}

func TestCIDRToRangeBin(t *testing.T) {
	tests := []struct {
		input string
		start []byte
		end   []byte
	}{
		{
			"10.0.0.0/24",
			[]byte{0x0a, 0x00, 0x00, 0x00},
			[]byte{0x0a, 0x00, 0x00, 0xff},
		},
		{
			"192.168.1.128/25",
			[]byte{0xc0, 0xa8, 0x01, 0x80},
			[]byte{0xc0, 0xa8, 0x01, 0xff},
		},
	}

	for _, tt := range tests {
		start, end, err := CIDRToRange(tt.input)
		//start, end, err := nftables.NetFirstAndLastIP(tt.input)
		ass.NoError(t, err)
		ass.Equal(t, tt.start, []byte(start))
		ass.Equal(t, tt.end, []byte(end))
	}
}

func Test_NextIP(t *testing.T) {
	type args struct {
		ip string
	}

	tests := []struct {
		name string
		args args
		want string
	}{
		// TODO: Add test cases.
		{
			name: "192.168.0.5",
			args: args{ip: "192.168.0.5"},
			want: "192.168.0.6",
		}, {
			name: "192.168.0.255",
			args: args{ip: "192.168.0.255"},
			want: "192.168.1.0",
		},

		//			"2001:0db8:85a3:0000:0000:8a2e:0370:7334",
		//			"::ffff",
		//			"255.255.255.255",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			if got := NextIP(net.ParseIP(tt.args.ip)); !reflect.DeepEqual(got.String(), tt.want) {
				t.Errorf("nextIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_IPRangeToCIDR(t *testing.T) {
	type args struct {
		startIP string
		endIP   string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		// TODO: Add test cases.
		{
			name: "single",
			args: args{startIP: "10.10.10.10", endIP: "10.10.10.10"},
			want: []string{"10.10.10.10"},
		},
		{
			name: "/24",
			args: args{startIP: "10.10.2.0", endIP: "10.10.2.255"},
			want: []string{"10.10.2.0/24"},
		},
		{
			name: "range",
			args: args{startIP: "10.10.2.0", endIP: "10.10.2.16"},
			want: []string{"10.10.2.0/28", "10.10.2.16"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IPRangeToCIDR(nil, tt.args.startIP, tt.args.endIP)
			//		got, err := rangeToCIDRs(net.ParseIP(tt.args.startIP), net.ParseIP(tt.args.endIP))
			if (err != nil) != tt.wantErr {
				t.Errorf("rangeToCIDRs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rangeToCIDRs() = %v, want %v", got, tt.want)
			}
		})
	}
}
