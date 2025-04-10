package main

import (
    "net"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

// MockNFT реализует интерфейс NFTables для тестов
type MockNFT struct {
    mock.Mock
}

func (m *MockNFT) CreateBlocklist() error {
    args := m.Called()
    return args.Error(0)
}

func (m *MockNFT) AddIP(ip net.IP) error {
    args := m.Called(ip)
    return args.Error(0)
}

func (m *MockNFT) RemoveIP(ip net.IP) error {
    args := m.Called(ip)
    return args.Error(0)
}

func (m *MockNFT) ListIPs() ([]net.IP, error) {
    args := m.Called()
    return args.Get(0).([]net.IP), args.Error(1)
}

func TestFirewallAddIP(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    testIP := "192.168.1.1"
    expectedIP := net.ParseIP(testIP).To4()

    mockNFT.On("AddIP", expectedIP).Return(nil)

    err := fw.AddIP(testIP)
    assert.NoError(t, err)
    mockNFT.AssertExpectations(t)
}

func TestFirewallAddInvalidIP(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    err := fw.AddIP("invalid-ip")
    assert.Error(t, err)
    mockNFT.AssertNotCalled(t, "AddIP")
}

func TestFirewallRemoveIP(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    testIP := "10.0.0.1"
    expectedIP := net.ParseIP(testIP).To4()

    mockNFT.On("RemoveIP", expectedIP).Return(nil)

    err := fw.RemoveIP(testIP)
    assert.NoError(t, err)
    mockNFT.AssertExpectations(t)
}

func TestFirewallListIPs(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    expectedIPs := []net.IP{
	net.ParseIP("192.168.1.1").To4(),
	net.ParseIP("10.0.0.2").To4(),
    }

    mockNFT.On("ListIPs").Return(expectedIPs, nil)

    ips, err := fw.ListIPs()
    assert.NoError(t, err)
    assert.Equal(t, []string{"192.168.1.1", "10.0.0.2"}, ips)
    mockNFT.AssertExpectations(t)
}

func TestCreateBlocklist(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    mockNFT.On("CreateBlocklist").Return(nil)

    err := fw.CreateBlocklist()
    assert.NoError(t, err)
    mockNFT.AssertExpectations(t)
}
