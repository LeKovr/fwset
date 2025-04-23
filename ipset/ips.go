package ipset

import "github.com/lrh3321/ipset-go"

type IPS interface {
	Create(setname, typename string, options ipset.CreateOptions) error
	Add(setname string, element *ipset.Entry) error
	Del(setname string, element *ipset.Entry) error
	List(setname string) (*ipset.Sets, error)
	Destroy(setname string) error
}
