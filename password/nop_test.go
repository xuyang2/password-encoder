package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNopPasswordEncoder_Encode(t *testing.T) {
	type args struct {
		rawPassword string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{args: args{rawPassword: "foo"}, want: "foo", wantErr: false},
		{args: args{rawPassword: "bar"}, want: "bar", wantErr: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NopPasswordEncoder()
			got, err := e.Encode(tt.args.rawPassword)
			if (err != nil) != tt.wantErr {
				t.Errorf("Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Encode() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNopPasswordEncoder_Matches(t *testing.T) {
	type args struct {
		rawPassword     string
		encodedPassword string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{args: args{rawPassword: "foo", encodedPassword: "foo"}, want: true},
		{args: args{rawPassword: "foo", encodedPassword: "FOO"}, want: false},
		{args: args{rawPassword: "foo", encodedPassword: "bar"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := NopPasswordEncoder()
			if got := e.Matches(tt.args.rawPassword, tt.args.encodedPassword); got != tt.want {
				t.Errorf("Matches() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNopPasswordEncoder_Upgradable(t *testing.T) {
	t.Run("always false", func(t *testing.T) {
		encoder := NopPasswordEncoder()

		assert.Equal(t, false, encoder.Upgradable("password"))
	})
}
