package host

import (
	"sync"

	plgpb "github.com/hashicorp/boundary/sdk/pbs/plugin"
)

type PluginMap struct {
	once sync.Once
	l    *sync.RWMutex
	m    map[string]plgpb.HostPluginServiceServer
}

func onceFunc(p *PluginMap) func() {
	return func() {
		p.l = new(sync.RWMutex)
		p.m = make(map[string]plgpb.HostPluginServiceServer)
	}
}

func (p *PluginMap) Set(name string, plg plgpb.HostPluginServiceServer) {
	p.once.Do(onceFunc(p))
	p.l.Lock()
	p.m[name] = plg
	p.l.Unlock()
}

func (p *PluginMap) Get(name string) plgpb.HostPluginServiceServer {
	p.once.Do(onceFunc(p))
	p.l.RLock()
	ret := p.m[name]
	p.l.RUnlock()
	return ret
}

func (p *PluginMap) Delete(name string) {
	p.once.Do(onceFunc(p))
	p.l.Lock()
	delete(p.m, name)
	p.l.Unlock()
}
