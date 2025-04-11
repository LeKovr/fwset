package fwset

import (
	"testing"

	"github.com/LeKovr/fwset/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var cfg = Config{
	Config: config.Config{
		TableName: "test_table",
		ChainName: "input",
		SetName:   "test_set",
	},
}

type MockNFT struct {
	mock.Mock
}

func (m *MockNFT) CreateBlocklist() error {
	return m.Called().Error(0)
}

func (m *MockNFT) ModifyIP(networks []string, add bool) error {
	return m.Called(networks).Error(0)
}

func (m *MockNFT) AddNetwork(networks []string) error {
	return m.Called(networks).Error(0)
}

func (m *MockNFT) RemoveNetwork(networks []string) error {
	return m.Called(networks).Error(0)
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
		//	{"Invalid", "invalid", true, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNFT := new(MockNFT)
			fw := &Firewall{config: cfg, handler: mockNFT}

			if tt.mockCall {
				mockNFT.On("AddNetwork", []string{tt.input}).Return(nil)
			}

			err := fw.AddNetwork([]string{tt.input})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockNFT.AssertExpectations(t)
		})
	}
}

func TestRemoveNetwork(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantErr  bool
		mockCall bool
	}{
		{"Valid IP", "192.168.1.1", false, true},
		{"Valid CIDR", "10.0.0.0/24", false, true},
		// {"Invalid", "invalid", true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockNFT := new(MockNFT)
			fw := &Firewall{config: cfg, handler: mockNFT}

			if tt.mockCall {
				mockNFT.On("RemoveNetwork", []string{tt.input}).Return(nil)
			}

			err := fw.RemoveNetwork([]string{tt.input})
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
	fw := &Firewall{config: cfg, handler: mockNFT}

	expected := []string{"192.168.1.1/32", "10.0.0.0/24"}
	mockNFT.On("ListNetworks").Return(expected, nil)

	result, err := fw.ListNetworks()
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
