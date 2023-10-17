// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package javagc

import (
	"context"
	"io"
	"log/slog"

	"github.com/cilium/ebpf"

	ebpfcommon "github.com/grafana/beyla/pkg/internal/ebpf/common"
	"github.com/grafana/beyla/pkg/internal/exec"
	"github.com/grafana/beyla/pkg/internal/goexec"
	"github.com/grafana/beyla/pkg/internal/imetrics"
	"github.com/grafana/beyla/pkg/internal/request"
	"github.com/grafana/beyla/pkg/internal/svc"
)

//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf ../../../../bpf/java_gc.c -- -I../../../../bpf/headers
//go:generate $BPF2GO -cc $BPF_CLANG -cflags $BPF_CFLAGS -target amd64,arm64 bpf_debug ../../../../bpf/java_gc.c -- -I../../../../bpf/headers -DBPF_DEBUG

type Tracer struct {
	Cfg        *ebpfcommon.TracerConfig
	Metrics    imetrics.Reporter
	bpfObjects bpfObjects
	closers    []io.Closer
}

func (p *Tracer) Load() (*ebpf.CollectionSpec, error) {
	loader := loadBpf
	if p.Cfg.BpfDebug {
		loader = loadBpf_debug
	}
	return loader()
}

func (p *Tracer) Constants(_ *exec.FileInfo, _ *goexec.Offsets) map[string]any {
	return make(map[string]any)
}

func (p *Tracer) BpfObjects() any {
	return &p.bpfObjects
}

func (p *Tracer) AddCloser(c ...io.Closer) {
	p.closers = append(p.closers, c...)
}

func (p *Tracer) GoProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) KProbes() map[string]ebpfcommon.FunctionPrograms {
	return nil
}

func (p *Tracer) UProbes() map[string]map[string]ebpfcommon.FunctionPrograms {
	return map[string]map[string]ebpfcommon.FunctionPrograms{
		"libjvm.so": {
			// This function encloses USDT for "mem__pool__gc__begin":
			"_ZN15GCMemoryManager8gc_beginEbbb": {
				Required: false,
				Start:    p.bpfObjects.UprobeMemPoolGcBegin,
			},
			// This function encloses USDT for "mem__pool__gc__end":
			"_ZN15GCMemoryManager6gc_endEbbbbN7GCCause5CauseEbPKc": {
				Required: false,
				Start:    p.bpfObjects.UprobeMemPoolGcEnd,
			},
			// Alternative to above:
			"_ZN15GCMemoryManager6gc_endEbbbbN7GCCause5CauseEb": {
				Required: false,
				Start:    p.bpfObjects.UprobeMemPoolGcEnd,
			},
		},
	}
}

func (p *Tracer) SocketFilters() []*ebpf.Program {
	return nil
}

func (p *Tracer) Run(ctx context.Context, eventsChan chan<- []request.Span, service svc.ID) {
	logger := slog.With("component", "javagc.Tracer")
	ebpfcommon.ForwardRingbuf[ebpfcommon.HTTPRequestTrace](
		service,
		p.Cfg, logger, p.bpfObjects.Events,
		ebpfcommon.ReadHTTPRequestTraceAsSpan,
		p.Metrics,
		append(p.closers, &p.bpfObjects)...,
	)(ctx, eventsChan)
}
