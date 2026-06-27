package policy

import (
	"fmt"
	"strings"
)

type Registry struct {
	policy    *Policy
	serverMap map[string]*Server
	toolMap   map[string]*ToolRule
}

func NewRegistry(p *Policy) *Registry {
	r := &Registry{
		policy:    p,
		serverMap: make(map[string]*Server),
		toolMap:   make(map[string]*ToolRule),
	}

	for i := range p.Servers {
		srv := &p.Servers[i]
		r.serverMap[srv.Name] = srv
		for j := range srv.Tools {
			tool := &srv.Tools[j]
			key := toolKey(srv.Name, tool.Name)
			r.toolMap[key] = tool
		}
	}

	return r
}

func (r *Registry) Policy() *Policy {
	return r.policy
}

func (r *Registry) Server(name string) (*Server, bool) {
	srv, ok := r.serverMap[name]
	return srv, ok
}

func (r *Registry) Tool(serverName, toolName string) (*ToolRule, bool) {
	tool, ok := r.toolMap[toolKey(serverName, toolName)]
	return tool, ok
}

func (r *Registry) FindTool(toolName string) (string, *ToolRule, bool) {
	for key, tool := range r.toolMap {
		parts := strings.SplitN(key, ":", 2)
		if len(parts) == 2 && parts[1] == toolName {
			return parts[0], tool, true
		}
	}
	return "", nil, false
}

func (r *Registry) IsServerAllowed(serverName string) bool {
	srv, ok := r.serverMap[serverName]
	if !ok {
		return r.policy.DefaultAction == ActionAllow
	}
	return srv.Allowed
}

func (r *Registry) IsToolAllowed(serverName, toolName string) (allowed bool, known bool) {
	tool, ok := r.toolMap[toolKey(serverName, toolName)]
	if !ok {
		return r.policy.DefaultAction == ActionAllow, false
	}
	return tool.Allowed, true
}

func (r *Registry) DefaultAction() Action {
	return r.policy.DefaultAction
}

func toolKey(server, tool string) string {
	return fmt.Sprintf("%s:%s", server, tool)
}
