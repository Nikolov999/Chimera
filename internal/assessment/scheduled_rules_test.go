package assessment

import (
	"testing"
	"time"

	"github.com/Nikolov999/chimera/internal/evidence"
	"github.com/Nikolov999/chimera/internal/scheduled"
)

func TestScheduledRulesDetectPhase050Conditions(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	entry := scheduled.Entry{
		ID:               "sch-test",
		Name:             "Privileged Job",
		Manager:          "WINDOWS_TASK_SCHEDULER",
		Kind:             "SCHEDULED_TASK",
		EnabledState:     "ENABLED",
		RuntimeState:     "READY",
		Account:          `ACME\AdminUser`,
		PrivilegeContext: "ADMINISTRATOR",
		Schedule:         "MSFT_TaskDailyTrigger",
		ActionExecutable: `C:\ProgramData\Acme\job.exe`,
		RunLevel:         "HIGHEST",
		LogonType:        "INTERACTIVE_TOKEN",
		HiddenState:      "YES",
		ActionPath: scheduled.PathPosture{
			Path: `C:\ProgramData\Acme\job.exe`, State: "OBSERVED", Exists: true, BroadlyWritable: true, PermissionBasis: "test",
		},
		ActionDirectoryPosture: scheduled.PathPosture{
			Path: `C:\ProgramData\Acme`, State: "OBSERVED", Exists: true, IsDirectory: true, BroadlyWritable: true, PermissionBasis: "test",
		},
		DefinitionPath: `TaskScheduler:\Acme\Privileged Job`,
		DefinitionPathPosture: scheduled.PathPosture{
			Path: `C:\Windows\System32\Tasks\Acme\Privileged Job`, State: "OBSERVED", Exists: true, PermissionBasis: "test",
		},
		DefinitionDirectoryPosture: scheduled.PathPosture{
			Path: `C:\Windows\System32\Tasks\Acme`, State: "OBSERVED", Exists: true, IsDirectory: true, PermissionBasis: "test",
		},
		ReferencedScriptPathPosture: scheduled.PathPosture{State: "NOT_APPLICABLE"},
		WorkingDirectoryPosture:     scheduled.PathPosture{State: "NOT_APPLICABLE"},
		CollectionSource:            "test",
		Confidence:                  evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("scheduled.platform", "windows", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("scheduled.inventory.count", 1, "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("scheduled.source.windows_task_scheduler", map[string]any{"item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("scheduled.item."+entry.ID, entry, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ScheduledRules(), obs, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]Finding{}
	for _, f := range findings {
		byID[f.RuleID] = f
	}
	if byID["CHM-SCH-001"].Status != StatusFail {
		t.Fatalf("action path rule = %s", byID["CHM-SCH-001"].Status)
	}
	if byID["CHM-SCH-003"].Status != StatusWarn {
		t.Fatalf("account rule = %s", byID["CHM-SCH-003"].Status)
	}
	if byID["CHM-SCH-004"].Status != StatusWarn {
		t.Fatalf("hidden rule = %s", byID["CHM-SCH-004"].Status)
	}
	if byID["CHM-SCH-005"].Status != StatusFail {
		t.Fatalf("directory rule = %s", byID["CHM-SCH-005"].Status)
	}
}

func TestScheduledDefinitionGroupWriteWarns(t *testing.T) {
	at := time.Unix(200, 0).UTC()
	entry := scheduled.Entry{
		ID:                          "sch-cron",
		Name:                        "root-job",
		Manager:                     "CRON",
		Kind:                        "CRON_ENTRY",
		EnabledState:                "ENABLED",
		RuntimeState:                "ON_DEMAND",
		Account:                     "root",
		PrivilegeContext:            "ROOT",
		Schedule:                    "@daily",
		ActionExecutable:            "/usr/bin/python3",
		ReferencedScriptPath:        "/opt/acme/job.py",
		ActionPath:                  scheduled.PathPosture{Path: "/usr/bin/python3", State: "OBSERVED", Exists: true, PermissionBasis: "test"},
		ActionDirectoryPosture:      scheduled.PathPosture{Path: "/usr/bin", State: "OBSERVED", Exists: true, IsDirectory: true, PermissionBasis: "test"},
		ReferencedScriptPathPosture: scheduled.PathPosture{Path: "/opt/acme/job.py", State: "OBSERVED", Exists: true, Group: "1000", GroupWritable: true, PermissionBasis: "test"},
		DefinitionPath:              "/etc/crontab",
		DefinitionPathPosture:       scheduled.PathPosture{Path: "/etc/crontab", State: "OBSERVED", Exists: true, Group: "0", PermissionBasis: "test"},
		DefinitionDirectoryPosture:  scheduled.PathPosture{Path: "/etc", State: "OBSERVED", Exists: true, IsDirectory: true, Group: "0", PermissionBasis: "test"},
		WorkingDirectoryPosture:     scheduled.PathPosture{State: "NOT_APPLICABLE"},
		HiddenState:                 "NOT_APPLICABLE", RunLevel: "NOT_APPLICABLE", LogonType: "CRON",
		CollectionSource: "test", Confidence: evidence.ConfidenceHigh,
	}
	obs := []evidence.Observation{
		evidence.NewObserved("scheduled.platform", "linux", "test", at, evidence.ConfidenceExact),
		evidence.NewObserved("scheduled.source.linux_cron", map[string]any{"item_count": 1}, "test", at, evidence.ConfidenceHigh),
		evidence.NewObserved("scheduled.item."+entry.ID, entry, "test", at, evidence.ConfidenceHigh),
	}
	findings, err := EvaluateRules(ScheduledRules(), obs, at.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		if f.RuleID == "CHM-SCH-002" {
			if f.Status != StatusWarn {
				t.Fatalf("expected WARN, got %s", f.Status)
			}
			return
		}
	}
	t.Fatal("CHM-SCH-002 finding missing")
}
