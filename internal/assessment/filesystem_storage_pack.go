package assessment

import (
	"fmt"
	"sort"
	"strings"
)

// FilesystemStoragePackVersion identifies the consolidated
// filesystem/storage posture pack. The pack is evaluation-only: it composes
// the existing read-only file-permission, ACL, mount, network-share, volume
// encryption, swap/pagefile, and hibernation rules without collecting or
// modifying host state.
const FilesystemStoragePackVersion = "chimera.rules/filesystem-storage-v1-phase086"

// filesystemStorageStableRuleIDs freezes the public finding
// namespace for filesystem and storage posture. These IDs are consumed by
// finding history, suppressions, exports, assessment diffs, and downstream
// integrations, so accidental removal or renumbering is a contract regression.
var filesystemStorageStableRuleIDs = []string{
	"CHM-FS-001", "CHM-FS-002", "CHM-FS-003", "CHM-FS-004", "CHM-FS-005",
	"CHM-FS-006", "CHM-FS-007", "CHM-FS-008", "CHM-FS-009", "CHM-FS-010",
	"CHM-FS-011", "CHM-FS-012", "CHM-FS-013", "CHM-FS-014", "CHM-FS-015",
	"CHM-FS-016", "CHM-FS-017", "CHM-FS-018", "CHM-FS-019", "CHM-FS-020",
	"CHM-STG-001", "CHM-STG-002", "CHM-STG-003", "CHM-STG-004",
}

// FilesystemStorageRulePack is the single composition point for the
// filesystem/storage workflow lane. It evaluates the normalized evidence from
// Phases 074-085 together so host-local file trust boundaries and persistent
// storage protection are represented by one deterministic stable-ID catalog.
func FilesystemStorageRulePack() []Rule {
	rules := append([]Rule(nil), FilesystemRules()...)
	rules = append(rules, StorageRules()...)
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	return rules
}

// FilesystemStorageRuleIDs returns a defensive copy of the frozen // CHM-FS/CHM-STG manifest.
func FilesystemStorageRuleIDs() []string {
	ids := append([]string(nil), filesystemStorageStableRuleIDs...)
	sort.Strings(ids)
	return ids
}

// ValidateFilesystemStorageRulePack enforces the public contract:
// every frozen ID exists exactly once, no unregistered filesystem/storage ID
// enters the pack, namespaces match categories, and every rule satisfies the
// normalized Chimera rule model.
func ValidateFilesystemStorageRulePack(rules []Rule) error {
	expected := make(map[string]struct{}, len(filesystemStorageStableRuleIDs))
	for _, id := range filesystemStorageStableRuleIDs {
		expected[id] = struct{}{}
	}
	seen := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("filesystem/storage rule %q invalid: %w", rule.ID, err)
		}
		if _, ok := expected[rule.ID]; !ok {
			return fmt.Errorf("unregistered filesystem/storage rule id %q", rule.ID)
		}
		if _, ok := seen[rule.ID]; ok {
			return fmt.Errorf("duplicate filesystem/storage rule id %q", rule.ID)
		}
		seen[rule.ID] = struct{}{}
		switch {
		case strings.HasPrefix(rule.ID, "CHM-FS-"):
			if rule.Category != "filesystem" {
				return fmt.Errorf("filesystem rule %q must use category filesystem, got %q", rule.ID, rule.Category)
			}
		case strings.HasPrefix(rule.ID, "CHM-STG-"):
			if rule.Category != "storage" {
				return fmt.Errorf("storage rule %q must use category storage, got %q", rule.ID, rule.Category)
			}
		default:
			return fmt.Errorf("rule %q is outside the filesystem/storage namespace", rule.ID)
		}
	}
	for id := range expected {
		if _, ok := seen[id]; !ok {
			return fmt.Errorf("stable filesystem/storage rule id %q is missing", id)
		}
	}
	if len(seen) != len(expected) {
		return fmt.Errorf("filesystem/storage rule count mismatch: got %d want %d", len(seen), len(expected))
	}
	return nil
}
