package session

import (
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
)

func TestClosedWith_validate(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := TestDefaultSession(t, conn, wrapper, iamRepo)
	sessionConnection := TestConnection(t, conn, session.PublicId, "127.0.0.1", 22, "127.0.0.1", 2222)
	type fields struct {
		ConnectionId string
		BytesUp      uint64
		BytesDown    uint64
		ClosedReason ClosedReason
	}
	tests := []struct {
		name    string
		fields  fields
		wantErr bool
	}{
		{
			name: "valid",
			fields: fields{
				ConnectionId: sessionConnection.PublicId,
				BytesUp:      1,
				BytesDown:    2,
				ClosedReason: ConnectionClosedByUser,
			},
		},
		{
			name: "missing-ConnectionId",
			fields: fields{
				BytesUp:      1,
				BytesDown:    2,
				ClosedReason: ConnectionClosedByUser,
			},
			wantErr: true,
		},
		{
			name: "missing-ClosedReason",
			fields: fields{
				ConnectionId: sessionConnection.PublicId,
				BytesUp:      1,
				BytesDown:    2,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := CloseWith{
				ConnectionId: tt.fields.ConnectionId,
				BytesUp:      tt.fields.BytesUp,
				BytesDown:    tt.fields.BytesDown,
				ClosedReason: tt.fields.ClosedReason,
			}
			if err := c.validate(); (err != nil) != tt.wantErr {
				t.Errorf("ClosedWith.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
