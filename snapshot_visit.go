package process

import (
	"bytes"
	audit "github.com/vela-security/vela-audit"
	"github.com/vela-security/vela-public/assert"
	"github.com/vela-security/vela-public/auxlib"
)

func (snt *snapshot) Create(bkt assert.Bucket) {
	var err error
	for pid, proc := range snt.current {
		sim := &simple{}
		if !proc.IsNull() {
			sim.with(proc)
			goto create
		}

		proc, err = sim.by(pid)
		if err != nil {
			continue
		}

		if snt.Ignore(proc) {
			continue
		}

	create:
		snt.report.OnCreate(proc)
		key := auxlib.ToString(pid)
		bkt.Store(key, sim, 0)
		snt.onCreate.Do(proc, snt.co, func(err error) {
			audit.Errorf("%s process snapshot create fail %v", snt.Name(), err).From(snt.co.CodeVM()).Put()
		})
	}

}

func (snt *snapshot) Delete(bkt assert.Bucket) {
	for pid, val := range snt.delete {
		bkt.Delete(pid)
		snt.onDelete.Do(val, snt.co, func(err error) {
			audit.Errorf("%s process snapshot delete fail %v", snt.Name(), err).From(snt.co.CodeVM()).Put()
		})
	}
}

func (snt *snapshot) Update(bkt assert.Bucket) {
	for pid, p := range snt.update {
		sim := &simple{}
		sim.with(p)
		bkt.Store(pid, sim, 0)
		snt.onUpdate.Do(p, snt.co, func(err error) {
			audit.Errorf("%s process snapshot update fail %v", snt.Name(), err).From(snt.co.CodeVM()).Put()
		})
	}
}

func (snt *snapshot) debug() {
	var buff bytes.Buffer
	bkt := xEnv.Bucket(snt.bkt...)
	bkt.Range(func(s string, i interface{}) {
		buff.WriteString(s)
		buff.WriteByte(':')
		buff.WriteString(auxlib.ToString(i))
		buff.WriteByte(',')
		buff.WriteByte('\n')
	})
	xEnv.Error(buff.String())
}
func (snt *snapshot) doReport() {
	if !snt.enable {
		return
	}

	snt.report.do()
}
