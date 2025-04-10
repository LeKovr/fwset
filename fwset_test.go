package main

import (
    "net"
    "testing"

    "github.com/stretchr/testify/assert"
    "github.com/stretchr/testify/mock"
)

type MockNFT struct {
    mock.Mock
}

func (m *MockNFT) CreateBlocklist() error {
    return m.Called().Error(0)
}

func (m *MockNFT) AddNetwork(network string) error {
    return m.Called(network).Error(0)
}

func (m *MockNFT) RemoveNetwork(network string) error {
    return m.Called(network).Error(0)
}

func (m *MockNFT) ListNetworks() ([]string, error) {
    args := m.Called()
    return args.Get(0).([]string), args.Error(1)
}

func TestAddNetwork(t *testing.T) {
    tests := []struct {
	name     string
	input    string
	wantErr  bool
	mockCall bool
    }{
	{"Valid IP", "192.168.1.1", false, true},
	{"Valid CIDR", "10.0.0.0/24", false, true},
	{"Invalid", "invalid", true, false},
    }

    for _, tt := range tests {
	t.Run(tt.name, func(t *testing.T) {
	    mockNFT := new(MockNFT)
	    fw := NewFirewall(mockNFT)

	    if tt.mockCall {
		mockNFT.On("AddNetwork", tt.input).Return(nil)
	    }

	    err := fw.AddNetwork(tt.input)
	    if tt.wantErr {
		assert.Error(t, err)
	    } else {
		assert.NoError(t, err)
	    }
	    mockNFT.AssertExpectations(t)
	})
    }
}

func TestListNetworks(t *testing.T) {
    mockNFT := new(MockNFT)
    fw := NewFirewall(mockNFT)

    expected := []string{"192.168.1.1/32", "10.0.0.0/24"}
    mockNFT.On("ListNetworks").Return(expected, nil)

    result, err := fw.ListNetworks()
    assert.NoError(t, err)
    assert.Equal(t, expected, result)
}

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
	    ipnet, err := parseNetwork(tt.input)
	    if tt.wantErr {
		assert.Error(t, err)
		return
	    }
	    assert.NoError(t, err)
	    assert.Equal(t, tt.expected, ipnet.String())
	})
    }
}
