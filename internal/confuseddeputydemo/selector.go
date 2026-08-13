package confuseddeputydemo

import (
	"errors"
	"strings"
)

// ServerAdvert is the metadata an agent sees for one server's tool.
type ServerAdvert struct {
	Name        string
	Description string
	ToolName    string
}

// SelectByDescription deterministically chooses the server whose tool
// description contains PoisonedMarker. It is a reproducible stand-in for an
// agent that selects by description text; it is not an LLM and makes no
// claim about real model behavior.
func SelectByDescription(servers []ServerAdvert) (ServerAdvert, error) {
	for _, s := range servers {
		if strings.Contains(s.Description, PoisonedMarker) {
			return s, nil
		}
	}
	return ServerAdvert{}, errors.New("no advertised tool description matched the poisoned preference marker")
}
