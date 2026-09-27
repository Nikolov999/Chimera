package overview

import (
	"context"
	"os"
	"os/user"
	"runtime"
	"strings"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
)

const (
	SchemaVersion    = "chimera.overview/v1"
	CollectorName    = "overview"
	CollectorVersion = "overview/v1"
)

func Collect(ctx context.Context) Overview {
	o := Overview{
		EvidenceSchema: evidence.SchemaVersion,
		CollectedAt:    time.Now().UTC(),
		OS:             runtime.GOOS,
		Architecture:   runtime.GOARCH,
		LogicalCPUs:    runtime.NumCPU(),
		ListenerScope:  "tcp-listen",
	}
	if h, err := os.Hostname(); err == nil {
		o.Hostname = h
	} else {
		o.Degraded = append(o.Degraded, "hostname: "+err.Error())
	}
	if u, err := user.Current(); err == nil {
		o.CurrentUser = u.Username
	} else {
		o.Degraded = append(o.Degraded, "current user: "+err.Error())
	}
	collectPlatform(ctx, &o)
	o.Privilege = finalizePrivilege(o.Privilege)
	o.PrivilegeSchema = PrivilegeSchemaVersion
	if err := o.Privilege.Validate(); err != nil {
		o.Degraded = append(o.Degraded, "privilege context: "+err.Error())
	}
	if err := ctx.Err(); err != nil {
		msg := "collection timeout reached: " + err.Error()
		found := false
		for _, d := range o.Degraded {
			if strings.HasPrefix(d, "collection timeout reached:") {
				found = true
				break
			}
		}
		if !found {
			o.Degraded = append(o.Degraded, msg)
		}
	}
	o.Evidence = buildEvidence(o)
	return o
}
