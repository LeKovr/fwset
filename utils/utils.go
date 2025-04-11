package utils

import (
	"fmt"
	"net"
	"strings"

	"github.com/google/nftables"
)

func ParseNetwork(network string) (*net.IPNet, error) {
	if strings.Contains(network, "/") {
		_, ipnet, err := net.ParseCIDR(network)

		return ipnet, err
	}

	ip := net.ParseIP(network)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP/CIDR")
	}

	if ip.To4() != nil {
		return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
	}

	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

// Функция для преобразования CIDR в диапазон адресов.
func CIDRToRange(network string) (net.IP, net.IP, error) {
	var firstIP, lastIP net.IP

	if strings.Contains(network, "-") {
		ips := strings.Split(network, "-")

		firstIP = net.ParseIP(ips[0])
		if firstIP == nil {
			return nil, nil, fmt.Errorf("invalid First IP")
		}

		lastIP = net.ParseIP(ips[1])
		if lastIP == nil {
			return nil, nil, fmt.Errorf("invalid Last IP")
		}
	} else {
		ipnet, err := ParseNetwork(network) // добавим маску, если не было
		if err != nil {
			return nil, nil, err
		}

		firstIP, lastIP, err = nftables.NetFirstAndLastIP(ipnet.String())
		if err != nil {
			return nil, nil, err
		}
	}

	return firstIP, lastIP, nil
}

func NextIP(ip net.IP) net.IP {
	/*      ip := net.ParseIP(ipStr)
	        if ip == nil {
	                return "", fmt.Errorf("invalid IP address: %s", ipStr)
	        }
	*/
	// Определяем версию IP и нормализуем представление
	var bytes []byte
	if v4 := ip.To4(); v4 != nil {
		bytes = make([]byte, len(v4))
		copy(bytes, v4)
	} else {
		v6 := ip.To16()
		bytes = make([]byte, len(v6))
		copy(bytes, v6)
	}

	// Инкрементируем IP-адрес
	carry := 1
	for i := len(bytes) - 1; i >= 0; i-- {
		sum := int(bytes[i]) + carry
		bytes[i] = byte(sum % 256)

		carry = sum / 256
		if carry == 0 {
			break
		}
	}

	if carry != 0 {
		// return nil, fmt.Errorf("IP address overflow")
		return nil
	}

	return net.IP(bytes)
}

func PreviousIP(ip net.IP) net.IP {
	// Определяем версию IP и нормализуем представление
	var bytes []byte
	if v4 := ip.To4(); v4 != nil {
		bytes = make([]byte, len(v4))
		copy(bytes, v4)
	} else {
		v6 := ip.To16()
		bytes = make([]byte, len(v6))
		copy(bytes, v6)
	}

	// Декрементируем IP-адрес
	borrow := 1
	for i := len(bytes) - 1; i >= 0; i-- {
		current := int(bytes[i]) - borrow
		if current >= 0 {
			bytes[i] = byte(current)
			borrow = 0

			break
		}
		// Обрабатываем заем
		bytes[i] = 255
		borrow = 1
	}

	// Проверяем переполнение (все байты стали 255)
	if borrow != 0 {
		// return "", fmt.Errorf("IP address underflow")
		return nil
	}

	return net.IP(bytes)
}
