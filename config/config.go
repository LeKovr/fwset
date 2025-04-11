// package config hold common for any fw settings.
package config

type Config struct {
	TableName string `default:"myfirewall"                     description:"Table name" env:"TABLE"   long:"table"`
	ChainName string `default:"input"                          description:"Chain name" env:"CHAIN"   long:"chain"`
	SetName   string `default:"blocked_nets"                   description:"Set name"   env:"SET"     long:"set"`
	IsAccept  bool   `description:"Use Accept instead of Drop" env:"ACCEPT"             long:"accept"`
}
