package main

import (
	"net"
	"os"
	"testing"

	"github.com/google/nftables"
	"github.com/stretchr/testify/assert"
)

// MockNFTConn для тестирования без реального взаимодействия с nftables
type MockNFTConn struct {
	Tables   map[string]*nftables.Table
	Chains   []*nftables.Chain
	Rules    []*nftables.Rule
	Sets     []*nftables.Set
	Elements map[string][]nftables.SetElement
}

func NewMockNFTConn() *MockNFTConn {
	return &MockNFTConn{
		Tables:   make(map[string]*nftables.Table),
		Elements: make(map[string][]nftables.SetElement),
	}
}

func (m *MockNFTConn) AddTable(t *nftables.Table) *nftables.Table {
	rv, ok := m.Tables[t.Name]
	if ok {
		return rv
	}
	m.Tables[t.Name] = t
	return t
}
func (m *MockNFTConn) DelTable(t *nftables.Table) {
	delete(m.Tables, t.Name)
}

func (m *MockNFTConn) AddChain(c *nftables.Chain) *nftables.Chain {
	m.Chains = append(m.Chains, c)
	return c
}

func (m *MockNFTConn) AddRule(r *nftables.Rule) *nftables.Rule {
	m.Rules = append(m.Rules, r)
	return r
}

func (m *MockNFTConn) AddSet(s *nftables.Set, elements []nftables.SetElement) error {
	m.Sets = append(m.Sets, s)
	m.Elements[s.Name] = elements
	return nil
}

func (m *MockNFTConn) GetSetByName(t *nftables.Table, name string) (*nftables.Set, error) {
	for _, s := range m.Sets {
		if s.Name == name {
			return s, nil
		}
	}
	return nil, os.ErrNotExist
}

func (m *MockNFTConn) SetAddElements(s *nftables.Set, elements []nftables.SetElement) error {
	m.Elements[s.Name] = append(m.Elements[s.Name], elements...)
	return nil
}

func (m *MockNFTConn) SetDeleteElements(s *nftables.Set, elements []nftables.SetElement) error {
	for _, e := range elements {
		for i, existing := range m.Elements[s.Name] {
			if string(existing.Key) == string(e.Key) {
				m.Elements[s.Name] = append(m.Elements[s.Name][:i], m.Elements[s.Name][i+1:]...)
				break
			}
		}
	}
	return nil
}

func (m *MockNFTConn) GetSetElements(s *nftables.Set) ([]nftables.SetElement, error) {
	return m.Elements[s.Name], nil
}

func NewMockNFT(mockConn *MockNFTConn) *RealNFT {
	return &RealNFT{
		tableName: "myfirewall",
		chainName: "input",
		setName:   "blocked_nets",
		conn:      mockConn,
	}
}
func (m *MockNFTConn) Flush() error { return nil }

// Тесты с использованием моков
func TestCreateBlocklist(t *testing.T) {
	mockConn := NewMockNFTConn()

	nft := NewMockNFT(mockConn)
	nft.CreateBlocklist()

	if len(mockConn.Tables) != 1 || mockConn.Tables[nft.tableName].Name != nft.tableName {
		t.Error("Table not created")
	}
	if len(mockConn.Chains) != 1 || mockConn.Chains[0].Name != nft.chainName {
		t.Error("Chain not created")
	}
	if len(mockConn.Sets) != 1 || mockConn.Sets[0].Name != nft.setName {
		t.Error("Set not created")
	}
}

func TestModifyIP(t *testing.T) {
	mockConn := NewMockNFTConn()
	nft := NewMockNFT(mockConn)

	// Инициализация тестового сета
	mockConn.AddSet(&nftables.Set{Name: nft.setName}, nil)

	testIP := "192.168.1.1"

	// Тест добавления
	nft.ModifyIP(testIP, true)
	elements := mockConn.Elements[nft.setName]
	if len(elements) < 1 || net.IP(elements[0].Key).String() != testIP {
		t.Error("IP not added", mockConn)
	}

	// Тест удаления
	oldLen := len(mockConn.Elements[nft.setName])
	nft.ModifyIP(testIP+"/32", false)
	if len(mockConn.Elements[nft.setName]) == oldLen {
		t.Error("IP not removed")
	}
}

// Интеграционные тесты (требуют root)
func TestIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Требуются права root для интеграционных тестов")
	}

	nft, err := NewRealNFT()
	assert.NoError(t, err)
	t.Run("CreateAndList", func(t *testing.T) {
		nft.CreateBlocklist()
		defer cleanup(t, nft)

		// Проверка создания
		if !setExists(t, nft) {
			t.Error("Set не создан")
		}
	})

	t.Run("AddRemoveIP", func(t *testing.T) {
		testIP := "8.8.8.8"
		nft.CreateBlocklist()
		defer cleanup(t, nft)

		// Добавление
		nft.ModifyIP(testIP+"/32", true)
		if !ipInSet(t, nft, testIP) {
			t.Error("IP не добавлен")
		}

		// Удаление
		nft.ModifyIP(testIP+"/32", false)
		if ipInSet(t, nft, testIP) {
			t.Error("IP не удалён")
		}
	})
}

func setExists(t *testing.T, nft *RealNFT) bool {
	table := nft.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nft.tableName,
	})
	_, err := nft.conn.GetSetByName(table, nft.setName)
	return err == nil
}

func ipInSet(t *testing.T, nft *RealNFT, ip string) bool {
	table := nft.conn.AddTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nft.tableName,
	})
	set, err := nft.conn.GetSetByName(table, nft.setName)
	if err != nil {
		return false
	}

	elements, err := nft.conn.GetSetElements(set)
	if err != nil {
		return false
	}
	target := net.ParseIP(ip).To4()
	for _, e := range elements {
		if net.IP(e.Key).Equal(target) {
			return true
		}
	}
	return false
}

func cleanup(t *testing.T, nft *RealNFT) {
	nft.conn.DelTable(&nftables.Table{
		Family: nftables.TableFamilyIPv4,
		Name:   nft.tableName,
	})
	if err := nft.conn.Flush(); err != nil {
		t.Logf("Cleanup error: %v", err)
	}
}
