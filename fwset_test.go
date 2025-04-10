package main

import (
    "net"
    "os"
    "testing"

    "github.com/google/nftables"
)

// MockNFTConn для тестирования без реального взаимодействия с nftables
type MockNFTConn struct {
    Tables  []*nftables.Table
    Chains  []*nftables.Chain
    Rules   []*nftables.Rule
    Sets    []*nftables.Set
    Elements map[string][]nftables.SetElement
}

func (m *MockNFTConn) AddTable(t *nftables.Table) *nftables.Table {
    m.Tables = append(m.Tables, t)
    return t
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

func (m *MockNFTConn) Flush() error { return nil }

// Тесты с использованием моков
func TestCreateBlocklist(t *testing.T) {
    mockConn := &MockNFTConn{
	Elements: make(map[string][]nftables.SetElement),
    }
    
    // Подменяем реальное соединение моком
    originalNFTConn := nftConn
    nftConn = mockConn
    defer func() { nftConn = originalNFTConn }()

    createBlocklist()

    if len(mockConn.Tables) != 1 || mockConn.Tables[0].Name != tableName {
	t.Error("Table not created")
    }
    if len(mockConn.Chains) != 1 || mockConn.Chains[0].Name != chainName {
	t.Error("Chain not created")
    }
    if len(mockConn.Sets) != 1 || mockConn.Sets[0].Name != setName {
	t.Error("Set not created")
    }
}

func TestModifyIP(t *testing.T) {
    mockConn := &MockNFTConn{
	Elements: make(map[string][]nftables.SetElement),
    }
    originalNFTConn := nftConn
    nftConn = mockConn
    defer func() { nftConn = originalNFTConn }()

    // Инициализация тестового сета
    mockConn.AddSet(&nftables.Set{Name: setName}, nil)

    testIP := "192.168.1.1"
    
    // Тест добавления
    modifyIP(testIP, true)
    elements := mockConn.Elements[setName]
    if len(elements) != 1 || net.IP(elements[0].Key).String() != testIP {
	t.Error("IP not added")
    }

    // Тест удаления
    modifyIP(testIP, false)
    if len(mockConn.Elements[setName]) != 0 {
	t.Error("IP not removed")
    }
}

// Интеграционные тесты (требуют root)
func TestIntegration(t *testing.T) {
    if os.Getuid() != 0 {
	t.Skip("Требуются права root для интеграционных тестов")
    }

    t.Run("CreateAndList", func(t *testing.T) {
	createBlocklist()
	defer cleanup(t)

	// Проверка создания
	if !setExists(t) {
	    t.Error("Set не создан")
	}
    })

    t.Run("AddRemoveIP", func(t *testing.T) {
	testIP := "8.8.8.8"
	createBlocklist()
	defer cleanup(t)
	
	// Добавление
	modifyIP(testIP, true)
	if !ipInSet(t, testIP) {
	    t.Error("IP не добавлен")
	}

	// Удаление
	modifyIP(testIP, false)
	if ipInSet(t, testIP) {
	    t.Error("IP не удалён")
	}
    })
}

func setExists(t *testing.T) bool {
    conn := &nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })
    _, err := conn.GetSetByName(table, setName)
    return err == nil
}

func ipInSet(t *testing.T, ip string) bool {
    conn := &nftables.Conn{}
    table := conn.AddTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })
    set, err := conn.GetSetByName(table, setName)
    if err != nil {
	return false
    }

    elements, err := conn.GetSetElements(set)
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

func cleanup(t *testing.T) {
    conn := &nftables.Conn{}
    conn.DelTable(&nftables.Table{
	Family: nftables.TableFamilyIPv4,
	Name:   tableName,
    })
    if err := conn.Flush(); err != nil {
	t.Logf("Cleanup error: %v", err)
    }
}
