package finger

import (
	"encoding/json"
	"io/ioutil"
)

type Config struct {
	Information []Information `json:"Information"`
	Fingerprint []Fingerprint `json:"fingerprint"`
}

type Information struct {
	Name     string   `json:"name"`
	Scope    string   `json:"scope"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

type Fingerprint struct {
	Cms      string   `json:"cms"`
	Method   string   `json:"method"`
	Location string   `json:"location"`
	Keyword  []string `json:"keyword"`
}

var (
	Webfingerprint *Config
)

func LoadWebfingerprint(path string) error {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return err
	}

	var config Config
	err = json.Unmarshal(data, &config)
	if err != nil {
		return err
	}
	Webfingerprint = &config
	return nil
}

func GetWebfingerprint() *Config {
	return Webfingerprint
}
