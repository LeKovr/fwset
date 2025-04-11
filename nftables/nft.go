package nftables

import "github.com/google/nftables"

type NFT interface {
	AddTable(t *nftables.Table) *nftables.Table
	AddChain(c *nftables.Chain) *nftables.Chain
	AddSet(s *nftables.Set, elements []nftables.SetElement) error
	GetSetByName(t *nftables.Table, name string) (*nftables.Set, error)
	SetAddElements(s *nftables.Set, elements []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, elements []nftables.SetElement) error

	AddRule(r *nftables.Rule) *nftables.Rule
	Flush() error
	GetSetElements(s *nftables.Set) ([]nftables.SetElement, error)
	DelTable(t *nftables.Table)
}
