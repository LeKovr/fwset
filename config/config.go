// package config hold common for any fw settings.
package config

type Config struct {
	TableName     string `default:"myfirewall"   description:"Table name"      env:"TABLE"      long:"table"`
	ChainName     string `default:"input"        description:"Chain name"      env:"CHAIN"      long:"chain"`
	SetNameDrop   string `default:"blocked_nets" description:"Drop set name"   env:"SET_DROP"   long:"set_drop"`
	SetNameAccept string `default:"allowed_nets" description:"Accept set name" env:"SET_ACCEPT" long:"set_accept"`
}
