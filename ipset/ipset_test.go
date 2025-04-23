package ipset

import (
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/lrh3321/ipset-go"

	"github.com/stretchr/testify/assert"

	"github.com/LeKovr/fwset/config"
)

var cfg = config.Config{
	SetNameAccept: "test_accept",
	SetNameDrop:   "test_drop",
}

// MockNFTConn для тестирования без реального взаимодействия с nftables
type MockConn struct {
	Elements map[string][]ipset.Entry
}

func NewMockConn() *MockConn {
	return &MockConn{
		Elements: make(map[string][]ipset.Entry),
	}
}

func (m *MockConn) Create(setname, typename string, options ipset.CreateOptions) error {
	m.Elements[setname] = []ipset.Entry{}
	return nil
}

func (m *MockConn) Add(set string, element *ipset.Entry) error {
	m.Elements[set] = append(m.Elements[set], *element)
	return nil
}

func (m *MockConn) Del(set string, element *ipset.Entry) error {
	for i, existing := range m.Elements[set] {
		if string(existing.IP) == string(element.IP) &&
			string(existing.CIDR) == string(element.CIDR) {
			m.Elements[set] = append(m.Elements[set][:i], m.Elements[set][i+1:]...)
			break
		}
	}
	return nil
}

func (m *MockConn) List(set string) (*ipset.Sets, error) {
	return &ipset.Sets{Entries: m.Elements[set]}, nil
}

func (m *MockConn) Destroy(set string) error {
	delete(m.Elements, set)
	return nil
}

func (m *MockConn) Flush() error { return nil }

func NewMockFW(cfg config.Config, mockConn *MockConn) *FireWall {
	return &FireWall{
		config: cfg,
		//		tableName: "myfirewall",
		//		chainName: "input",
		//		setName:   "blocked_nets",
		conn: mockConn,
	}
}

// Тесты с использованием моков
func TestCreateBlocklist(t *testing.T) {
	mockConn := NewMockConn()

	nft := NewMockFW(cfg, mockConn)
	nft.Create(false)

	if _, ok := mockConn.Elements[cfg.SetNameDrop]; !ok {
		t.Error("Set not created")
	}
}

func TestModify(t *testing.T) {
	mockConn := NewMockConn()
	nft := NewMockFW(cfg, mockConn)

	// Инициализация тестового сета
	mockConn.Create(nft.config.SetNameDrop, "", ipset.CreateOptions{})

	testIP := "192.168.1.1"

	// Тест добавления
	nft.Modify(false, true, []string{testIP})
	elements := mockConn.Elements[nft.config.SetNameDrop]
	if len(elements) < 1 || net.IP(elements[0].IP).String() != testIP {
		t.Error("IP not added", mockConn)
	}

	// Тест удаления
	oldLen := len(mockConn.Elements[nft.config.SetNameDrop])
	nft.Modify(false, false, []string{testIP + "/32"})
	if len(mockConn.Elements[nft.config.SetNameDrop]) == oldLen {
		t.Error("IP not removed")
	}
}

// Интеграционные тесты (требуют root)
func TestIntegration(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Требуются права root для интеграционных тестов")
	}

	nft, err := New(cfg)
	assert.NoError(t, err)
	t.Run("CreateAndList", func(t *testing.T) {
		nft.Create(false)
		defer cleanup(t, nft, false)

		// Проверка создания
		if !setExists(t, nft, false) {
			t.Error("Set не создан")
		}
	})

	t.Run("AddRemoveIP", func(t *testing.T) {
		testIP := "8.8.8.8"
		nft.Create(false)
		defer cleanup(t, nft, false)

		// Добавление
		nft.Modify(false, true, []string{testIP + "/32"})
		if !ipInSet(t, nft, false, testIP) {
			t.Error("IP не добавлен")
		}

		// Удаление
		nft.Modify(false, false, []string{testIP + "/32"})
		if ipInSet(t, nft, false, testIP) {
			t.Error("IP не удалён")
		}
	})
}

func setExists(t *testing.T, nft *FireWall, accept bool) bool {
	t.Helper()

	setname := nft.setName(accept)
	_, err := nft.conn.List(setname)
	return err == nil
}

func ipInSet(t *testing.T, nft *FireWall, accept bool, ip string) bool {
	t.Helper()
	setname := nft.setName(accept)
	conn := nft.conn
	set, err := conn.List(setname)
	if err != nil {
		return false
	}
	for _, e := range set.Entries {
		network := e.IP.String()
		if e.CIDR != 32 {
			network = fmt.Sprintf("%s/%d", network, e.CIDR)
		}
		if network == ip {
			return true
		}
	}
	return false
}

func cleanup(t *testing.T, nft *FireWall, accept bool) {
	setname := nft.setName(accept)
	if err := nft.conn.Destroy(setname); err != nil {
		t.Logf("Destroy error: %v", err)
		return
	}

}
