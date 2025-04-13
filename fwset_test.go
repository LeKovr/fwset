package fwset

import (
	"testing"

	"github.com/LeKovr/fwset/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var cfg = Config{
	Config: config.Config{
		TableName:   "test_table",
		ChainName:   "input",
		SetNameDrop: "test_set",
	},
}

type MockNFT struct {
	mock.Mock
}

func (m *MockNFT) Create(accept bool) error {
	return m.Called(accept).Error(0)
}

func (m *MockNFT) ModifyIP(accept, add bool, networks []string) error {
	return m.Called(accept, add, networks).Error(0)
}

func (m *MockNFT) Add(accept bool, networks []string) error {
	return m.Called(accept, networks).Error(0)
}

func (m *MockNFT) Remove(accept bool, networks []string) error {
	return m.Called(accept, networks).Error(0)
}

func (m *MockNFT) List(accept bool) ([]string, error) {
	args := m.Called(accept)
	return args.Get(0).([]string), args.Error(1)
}

func TestAdd(t *testing.T) {
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
				mockNFT.On("Add", false, []string{tt.input}).Return(nil)
			}

			err := fw.Add(false, []string{tt.input})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockNFT.AssertExpectations(t)
		})
	}
}

func TestRemove(t *testing.T) {
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
				mockNFT.On("Remove", false, []string{tt.input}).Return(nil)
			}

			err := fw.Remove(false, []string{tt.input})
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			mockNFT.AssertExpectations(t)
		})
	}
}

func TestList(t *testing.T) {
	mockNFT := new(MockNFT)
	fw := &Firewall{config: cfg, handler: mockNFT}

	expected := []string{"192.168.1.1/32", "10.0.0.0/24"}
	mockNFT.On("List", false).Return(expected, nil)

	result, err := fw.List(false)
	assert.NoError(t, err)
	assert.Equal(t, expected, result)
}
