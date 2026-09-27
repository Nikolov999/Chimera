package render

import (
	"fmt"
	"io"
	"strings"

	"github.com/Nikolov999/chimera/internal/accounts"
)

func AccountsHuman(w io.Writer, inv accounts.Inventory, verbose bool) {
	fmt.Fprintln(w, "ACCOUNTS")
	fmt.Fprintf(w, "  Schema             %s\n", inv.Schema)
	fmt.Fprintf(w, "  Collector          %s\n", inv.CollectorVersion)
	fmt.Fprintf(w, "  Platform           %s/%s\n", inv.Platform, inv.Architecture)
	fmt.Fprintf(w, "  Collected          %s\n", inv.CollectedAt.Format("2006-01-02T15:04:05Z07:00"))

	fmt.Fprintln(w, "\nSUMMARY")
	fmt.Fprintf(w, "  Accounts           %d\n", inv.Summary.Accounts)
	fmt.Fprintf(w, "  Groups             %d\n", inv.Summary.Groups)
	fmt.Fprintf(w, "  Enabled            %d\n", inv.Summary.Enabled)
	fmt.Fprintf(w, "  Disabled           %d\n", inv.Summary.Disabled)
	fmt.Fprintf(w, "  Enabled unknown    %d\n", inv.Summary.EnabledUnknown)
	fmt.Fprintf(w, "  Login capable      %d\n", inv.Summary.LoginCapable)
	fmt.Fprintf(w, "  Login disabled     %d\n", inv.Summary.LoginDisabled)
	fmt.Fprintf(w, "  Privileged         %d\n", inv.Summary.Privileged)
	fmt.Fprintf(w, "  Service accounts   %d\n", inv.Summary.ServiceAccounts)
	fmt.Fprintf(w, "  Human accounts     %d\n", inv.Summary.HumanAccounts)
	fmt.Fprintf(w, "  System accounts    %d\n", inv.Summary.SystemAccounts)
	fmt.Fprintf(w, "  Auth observed      %d\n", inv.Summary.AuthObserved)
	fmt.Fprintf(w, "  Auth degraded      %d\n", inv.Summary.AuthDegraded)
	fmt.Fprintf(w, "  Empty password     %d\n", inv.Summary.EmptyPasswordObserved)
	fmt.Fprintf(w, "  Password not req.  %d\n", inv.Summary.PasswordNotRequired)
	fmt.Fprintf(w, "  Password state ?   %d\n", inv.Summary.PasswordStateUnknown)
	fmt.Fprintf(w, "  Password req. ?    %d\n", inv.Summary.PasswordRequirementUnknown)

	fmt.Fprintln(w, "\nPROVIDERS")
	if len(inv.Sources) == 0 {
		fmt.Fprintln(w, "  No provider status returned.")
	}
	for _, src := range inv.Sources {
		fmt.Fprintf(w, "  %-28s %-14s items=%d  %s\n", src.ID, strings.ToUpper(string(src.State)), src.ItemCount, src.Source)
		if verbose && src.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", truncate(src.Reason, 140))
		}
	}

	fmt.Fprintln(w, "\nLOCAL ACCOUNTS")
	if len(inv.Accounts) == 0 {
		fmt.Fprintln(w, "  No local account records were returned by the available provider.")
	}
	for _, a := range inv.Accounts {
		flags := []string{a.EnabledState, a.LoginCapability, a.AccountType}
		if a.Privileged {
			flags = append(flags, "PRIVILEGED")
		}
		if a.ServiceAccount {
			flags = append(flags, "SERVICE")
		}
		fmt.Fprintf(w, "  %-30s %-14s %s\n", truncate(a.Principal, 30), truncate(a.Authentication.PasswordState, 14), strings.Join(flags, ","))
		if verbose {
			fmt.Fprintf(w, "    id:           %s\n", a.ID)
			if a.UID != "" || a.GID != "" {
				fmt.Fprintf(w, "    uid/gid:      %s/%s\n", fallbackRender(a.UID, "-"), fallbackRender(a.GID, "-"))
			}
			if a.SID != "" {
				fmt.Fprintf(w, "    sid:          %s\n", a.SID)
			}
			if a.Home != "" {
				fmt.Fprintf(w, "    home:         %s\n", truncate(a.Home, 120))
			}
			if a.Shell != "" {
				fmt.Fprintf(w, "    shell:        %s\n", truncate(a.Shell, 120))
			}
			if len(a.Groups) > 0 {
				fmt.Fprintf(w, "    groups:       %s\n", truncate(strings.Join(a.Groups, ", "), 160))
			}
			if len(a.PrivilegeBasis) > 0 {
				fmt.Fprintf(w, "    privilege:    %s\n", truncate(strings.Join(a.PrivilegeBasis, "; "), 160))
			}
			if len(a.ServiceBasis) > 0 {
				fmt.Fprintf(w, "    service-basis:%s\n", truncate(strings.Join(a.ServiceBasis, "; "), 160))
			}
			fmt.Fprintf(w, "    auth:         state=%s required=%s expires=%s changeable=%s\n", a.Authentication.State, a.Authentication.PasswordRequired, a.Authentication.PasswordExpires, a.Authentication.PasswordChangeable)
			if a.Authentication.LastLogin != "" {
				fmt.Fprintf(w, "    last-login:   %s\n", a.Authentication.LastLogin)
			}
			if a.Authentication.LastPasswordChange != "" {
				fmt.Fprintf(w, "    password-age: %s\n", a.Authentication.LastPasswordChange)
			}
			if a.Authentication.Reason != "" {
				fmt.Fprintf(w, "    auth-note:    %s\n", truncate(a.Authentication.Reason, 140))
			}
			fmt.Fprintf(w, "    source:       %s\n", a.CollectionSource)
			fmt.Fprintf(w, "    confidence:   %s\n", a.Confidence)
		}
	}

	fmt.Fprintln(w, "\nWINDOWS LOCAL SECURITY POLICY")
	fmt.Fprintf(w, "  %-28s %s\n", "Provider state", inv.SecurityPolicy.State)
	if len(inv.SecurityPolicy.Controls) == 0 {
		fmt.Fprintln(w, "  No Windows UAC/local-security-policy controls were returned.")
	}
	for _, c := range inv.SecurityPolicy.Controls {
		value := c.Value
		if value == "" {
			value = string(c.State)
		}
		fmt.Fprintf(w, "  %-28s %s\n", truncate(c.Name, 28), truncate(value, 56))
		if verbose && c.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", truncate(c.Reason, 140))
		}
	}
	if verbose && inv.SecurityPolicy.Reason != "" {
		fmt.Fprintf(w, "    provider-note: %s\n", truncate(inv.SecurityPolicy.Reason, 160))
	}

	fmt.Fprintln(w, "\nWINDOWS CREDENTIAL PROTECTION")
	fmt.Fprintf(w, "  %-28s %s\n", "Provider state", inv.CredentialProtection.State)
	if len(inv.CredentialProtection.Controls) == 0 {
		fmt.Fprintln(w, "  No Windows credential-protection controls were returned.")
	}
	for _, c := range inv.CredentialProtection.Controls {
		value := c.Value
		if value == "" {
			value = string(c.State)
		}
		fmt.Fprintf(w, "  %-28s %s\n", truncate(c.Name, 28), truncate(value, 56))
		if verbose && c.Reason != "" {
			fmt.Fprintf(w, "    reason: %s\n", truncate(c.Reason, 140))
		}
	}
	if verbose && inv.CredentialProtection.Reason != "" {
		fmt.Fprintf(w, "    provider-note: %s\n", truncate(inv.CredentialProtection.Reason, 160))
	}

	fmt.Fprintln(w, "\nLINUX SUDO / SUDOERS POSTURE")
	fmt.Fprintf(w, "  %-28s %s\n", "Provider state", inv.SudoPosture.State)
	fmt.Fprintf(w, "  %-28s %d\n", "Parsed files", inv.SudoPosture.Summary.ParsedFiles)
	fmt.Fprintf(w, "  %-28s %d\n", "Delegation rules", inv.SudoPosture.Summary.Grants)
	fmt.Fprintf(w, "  %-28s %d\n", "Broad NOPASSWD", inv.SudoPosture.Summary.BroadNOPASSWDCommands)
	fmt.Fprintf(w, "  %-28s %d\n", "Unrestricted commands", inv.SudoPosture.Summary.UnrestrictedCommands)
	fmt.Fprintf(w, "  %-28s %d\n", "Unsafe environment", inv.SudoPosture.Summary.UnsafeEnvironment)
	fmt.Fprintf(w, "  %-28s %d\n", "Writable references", inv.SudoPosture.Summary.WritableReferences)
	fmt.Fprintf(w, "  %-28s %d\n", "Insecure config paths", inv.SudoPosture.Summary.InsecureConfigPaths)
	if verbose {
		for _, issue := range inv.SudoPosture.EnvironmentIssues {
			fmt.Fprintf(w, "  ENV  %-22s %s:%d\n", truncate(issue.Kind, 22), truncate(issue.Source, 72), issue.Line)
			if len(issue.Values) > 0 {
				fmt.Fprintf(w, "       variables: %s\n", truncate(strings.Join(issue.Values, ", "), 120))
			}
		}
		for _, issue := range inv.SudoPosture.PathIssues {
			fmt.Fprintf(w, "  PATH %-22s %s\n", truncate(issue.Kind, 22), truncate(issue.Path, 96))
			fmt.Fprintf(w, "       reason: %s\n", truncate(issue.Reason, 150))
		}
		for _, cfg := range inv.SudoPosture.ConfigPaths {
			if !cfg.Insecure {
				continue
			}
			fmt.Fprintf(w, "  CFG  %-22s %s\n", truncate(cfg.Kind, 22), truncate(cfg.Path, 96))
			fmt.Fprintf(w, "       reason: %s\n", truncate(strings.Join(cfg.InsecureBasis, "; "), 150))
		}
	}
	if verbose && inv.SudoPosture.Reason != "" {
		fmt.Fprintf(w, "    provider-note: %s\n", truncate(inv.SudoPosture.Reason, 160))
	}

	fmt.Fprintln(w, "\nLINUX PAM / LOGIN POLICY")
	fmt.Fprintf(w, "  %-28s %s\n", "Provider state", inv.LinuxAuthPosture.State)
	fmt.Fprintf(w, "  %-28s %d\n", "Parsed files", inv.LinuxAuthPosture.Summary.ParsedFiles)
	fmt.Fprintf(w, "  %-28s %d\n", "PAM rules", inv.LinuxAuthPosture.Summary.PAMRules)
	fmt.Fprintf(w, "  %-28s %d\n", "Lockout rules", inv.LinuxAuthPosture.Summary.LockoutRules)
	fmt.Fprintf(w, "  %-28s %d\n", "Quality rules", inv.LinuxAuthPosture.Summary.QualityRules)
	fmt.Fprintf(w, "  %-28s %d\n", "History rules", inv.LinuxAuthPosture.Summary.HistoryRules)
	fmt.Fprintf(w, "  %-28s %d\n", "Null-password rules", inv.LinuxAuthPosture.Summary.NullOKRules)
	fmt.Fprintf(w, "  %-28s %d\n", "Permissive rules", inv.LinuxAuthPosture.Summary.PermitRules)
	fmt.Fprintf(w, "  %-28s %d\n", "Insecure config paths", inv.LinuxAuthPosture.Summary.InsecureConfigPaths)
	if inv.LinuxAuthPosture.LoginPolicy.State == "OBSERVED" {
		fmt.Fprintf(w, "  %-28s max=%d min=%d warn=%d hash=%s\n", "login.defs password policy", inv.LinuxAuthPosture.LoginPolicy.MaxDays, inv.LinuxAuthPosture.LoginPolicy.MinDays, inv.LinuxAuthPosture.LoginPolicy.WarnAge, fallbackRender(inv.LinuxAuthPosture.LoginPolicy.EncryptMethod, "default/unspecified"))
	}
	if verbose {
		for _, rule := range inv.LinuxAuthPosture.PAMRules {
			if rule.Module != "pam_faillock.so" && rule.Module != "pam_tally2.so" && rule.Module != "pam_tally.so" && rule.Module != "pam_pwquality.so" && rule.Module != "pam_passwdqc.so" && rule.Module != "pam_cracklib.so" && rule.Module != "pam_pwhistory.so" && rule.Module != "pam_unix.so" && rule.Module != "pam_permit.so" {
				continue
			}
			fmt.Fprintf(w, "  PAM  %-18s %-10s %-22s %s:%d\n", truncate(rule.Service, 18), truncate(rule.Type, 10), truncate(rule.Module, 22), truncate(rule.Source, 68), rule.Line)
		}
		for _, cfg := range inv.LinuxAuthPosture.ConfigPaths {
			if !cfg.Insecure {
				continue
			}
			fmt.Fprintf(w, "  CFG  %-18s %s\n", truncate(cfg.Kind, 18), truncate(cfg.Path, 96))
			fmt.Fprintf(w, "       reason: %s\n", truncate(strings.Join(cfg.InsecureBasis, "; "), 150))
		}
	}
	if verbose && inv.LinuxAuthPosture.Reason != "" {
		fmt.Fprintf(w, "    provider-note: %s\n", truncate(inv.LinuxAuthPosture.Reason, 160))
	}

	fmt.Fprintln(w, "\nSSH KEY / AUTHORIZED_KEYS POSTURE")
	fmt.Fprintf(w, "  %-28s %s\n", "Provider state", inv.SSHKeyPosture.State)
	fmt.Fprintf(w, "  %-28s %d\n", "SSH directories", inv.SSHKeyPosture.Summary.SSHDirectories)
	fmt.Fprintf(w, "  %-28s %d\n", "authorized_keys files", inv.SSHKeyPosture.Summary.AuthorizedKeysFiles)
	fmt.Fprintf(w, "  %-28s %d\n", "Private-key candidates", inv.SSHKeyPosture.Summary.PrivateKeyCandidates)
	fmt.Fprintf(w, "  %-28s %d\n", "Privileged auth.keys", inv.SSHKeyPosture.Summary.PrivilegedAuthorizedKeysFiles)
	fmt.Fprintf(w, "  %-28s %d\n", "Insecure SSH dirs", inv.SSHKeyPosture.Summary.InsecureSSHDirectories)
	fmt.Fprintf(w, "  %-28s %d\n", "Insecure auth.keys", inv.SSHKeyPosture.Summary.InsecureAuthorizedKeysFiles)
	fmt.Fprintf(w, "  %-28s %d\n", "Insecure private keys", inv.SSHKeyPosture.Summary.InsecurePrivateKeyCandidates)
	if verbose {
		for _, r := range inv.SSHKeyPosture.Records {
			if r.State != "OBSERVED" || !r.Insecure {
				continue
			}
			fmt.Fprintf(w, "  %-6s %-26s %s\n", truncate(r.Kind, 6), truncate(r.Principal, 26), truncate(r.Path, 88))
			fmt.Fprintf(w, "         reason: %s\n", truncate(strings.Join(r.InsecureBasis, "; "), 150))
		}
	}
	if verbose && inv.SSHKeyPosture.Reason != "" {
		fmt.Fprintf(w, "    provider-note: %s\n", truncate(inv.SSHKeyPosture.Reason, 160))
	}

	if verbose {
		fmt.Fprintln(w, "\nLOCAL GROUPS")
		for _, g := range inv.Groups {
			marker := ""
			if g.Privileged {
				marker = " PRIVILEGED"
			}
			fmt.Fprintf(w, "  %-30s members=%-4d%s\n", truncate(g.Name, 30), len(g.Members), marker)
			if len(g.Members) > 0 {
				fmt.Fprintf(w, "    members: %s\n", truncate(strings.Join(g.Members, ", "), 180))
			}
		}
	}

	if verbose && len(inv.Degraded) > 0 {
		fmt.Fprintln(w, "\nDEGRADED EVIDENCE")
		for _, d := range inv.Degraded {
			fmt.Fprintln(w, "  - "+truncate(d, 160))
		}
	}
}
