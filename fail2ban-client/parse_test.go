package fail2ban_client

import (
	"reflect"
	"testing"
	"time"
)

func Test_parse(t *testing.T) {
	layout := "2006-01-02 15:04:05"

	t1, _ := time.Parse(layout, "2023-10-27 10:00:00")
	t2, _ := time.Parse(layout, "2023-10-27 11:00:00")

	tests := []struct {
		name    string
		entry   string
		want    *parsedEntry
		wantErr bool
	}{
		{
			name:  "valid IPv4",
			entry: "1.2.3.4 2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "1.2.3.4",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
		{
			name:  "valid IPv6",
			entry: "2001:db8::1 2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "2001:db8::1",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
		{
			name:  "valid IPv6 localhost",
			entry: "::1 2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "::1",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
		{
			name:  "valid IPv4",
			entry: "5.5.5.5 2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "5.5.5.5",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
		{
			name:    "invalid IP",
			entry:   "invalid-ip 2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid bannedAt date",
			entry:   "1.2.3.4 2023-13-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "invalid banEndsAt date",
			entry:   "1.2.3.4 2023-10-27 10:00:00 + 3600 = 2023-10-32 11:00:00",
			want:    nil,
			wantErr: true,
		},
		{
			name:    "malformed entry",
			entry:   "1.2.3.4 2023-10-27 10:00:00 + 3600",
			want:    nil,
			wantErr: true,
		},
		{
			name:  "valid IPv4 with tabs",
			entry: "1.2.3.4\t2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "1.2.3.4",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
		{
			name:  "valid IPv6 with tabs",
			entry: "2001:db8::1\t2023-10-27 10:00:00 + 3600 = 2023-10-27 11:00:00",
			want: &parsedEntry{
				ipAddress:      "2001:db8::1",
				currentPenalty: "3600",
				bannedAt:       t1,
				banEndsAt:      t2,
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parse(tt.entry)
			if (err != nil) != tt.wantErr {
				t.Errorf("parse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parse() got = %v, want %v", got, tt.want)
			}
		})
	}
}
