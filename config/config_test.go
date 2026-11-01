package config

import "testing"

func TestCanBanAndCanUnban(t *testing.T) {
	tests := []struct {
		name          string
		configuration Configuration
		jail          string
		wantBan       bool
		wantUnban     bool
		wantActions   bool
	}{
		{
			name:          "nothing allowed by default",
			configuration: Configuration{},
			jail:          "sshd",
		},
		{
			name:          "all jails allowed",
			configuration: Configuration{AllowBanAll: true, AllowUnbanAll: true},
			jail:          "sshd",
			wantBan:       true,
			wantUnban:     true,
			wantActions:   true,
		},
		{
			name:          "listed jail allowed",
			configuration: Configuration{AllowBanJails: []string{"postfix", "sshd"}, AllowUnbanJails: []string{"sshd"}},
			jail:          "sshd",
			wantBan:       true,
			wantUnban:     true,
			wantActions:   true,
		},
		{
			name:          "unlisted jail not allowed",
			configuration: Configuration{AllowBanJails: []string{"postfix"}, AllowUnbanJails: []string{"doesnotexist"}},
			jail:          "sshd",
			wantActions:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.configuration.CanBan(tt.jail); got != tt.wantBan {
				t.Errorf("CanBan(%q) = %v, want %v", tt.jail, got, tt.wantBan)
			}
			if got := tt.configuration.CanUnban(tt.jail); got != tt.wantUnban {
				t.Errorf("CanUnban(%q) = %v, want %v", tt.jail, got, tt.wantUnban)
			}
			if got := tt.configuration.HasBanActions(); got != tt.wantActions {
				t.Errorf("HasBanActions() = %v, want %v", got, tt.wantActions)
			}
		})
	}
}
