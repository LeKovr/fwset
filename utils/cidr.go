package utils

// Code from https://go.dev/play/p/Ynx1liLAGs2
// Found at https://groups.google.com/g/golang-nuts/c/rJvVwk4jwjQ/m/gqtcpuKgp2YJ

import (
	"errors"
	"math/big"
	"net/netip"
	"strconv"
)

// Verify the result in the following way
// https://www.ipaddressguide.com/cidr
// https://www.ipaddressguide.com/ipv6-cidr

func IPRangeToCIDR(cidr []string, start, end string) ([]string, error) {
	if start == end {
		return []string{start}, nil
	}

	ips, err := netip.ParseAddr(start)
	if err != nil {
		return nil, err
	}

	ipe, err := netip.ParseAddr(end)
	if err != nil {
		return nil, err
	}

	isV4 := ips.Is4()
	if isV4 != ipe.Is4() {
		return nil, errors.New("start and end types are different")
	}

	if ips.Compare(ipe) > 0 {
		return nil, errors.New("start > end")
	}

	var (
		ipsInt = new(big.Int).SetBytes(ips.AsSlice())
		ipeInt = new(big.Int).SetBytes(ipe.AsSlice())
		tmpInt = new(big.Int)
		mask   = new(big.Int)
		one    = big.NewInt(1)
		buf    []byte

		bits, maxBit uint
	)

	if isV4 {
		maxBit = 32
		buf = make([]byte, 4)
	} else {
		maxBit = 128
		buf = make([]byte, 16)
	}

	for {
		bits = 1

		mask.SetUint64(1)

		for bits < maxBit {
			if (tmpInt.Or(ipsInt, mask).Cmp(ipeInt) > 0) ||
				(tmpInt.Lsh(tmpInt.Rsh(ipsInt, bits), bits).Cmp(ipsInt) != 0) {
				bits--

				mask.Rsh(mask, 1)

				break
			}

			bits++

			mask.Add(mask.Lsh(mask, 1), one)
		}

		addr, _ := netip.AddrFromSlice(ipsInt.FillBytes(buf))
		maskStr := strconv.FormatUint(uint64(maxBit-bits), 10)
		rv := addr.String()

		if maskStr != "32" {
			rv += "/" + maskStr
		}

		cidr = append(cidr, rv)

		if tmpInt.Or(ipsInt, mask); tmpInt.Cmp(ipeInt) >= 0 {
			break
		}

		ipsInt.Add(tmpInt, one)
	}

	return cidr, nil
}

/*
func main() {
    start, end := "10.5.6.0", "10.23.25.255"
    cidr, err := IpRangeToCIDR(nil, start, end)
    if err != nil {
	panic(err)
    }
    fmt.Println(strings.Join(cidr, "\n"))

    start = "2001:4860:4860:0000:0000:0000:0000:8888"
    end = "2001:4860:4860:0000:0000:0000:4567:1234"
    cidr, err = IpRangeToCIDR(cidr[:0], start, end)
    if err != nil {
	panic(err)
    }
    fmt.Println(strings.Join(cidr, "\n"))
}
*/
