// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ssh_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/hashicorp/boundary/internal/bsr"
	pssh "github.com/hashicorp/boundary/internal/bsr/gen/ssh/v1"
	"github.com/hashicorp/boundary/internal/bsr/ssh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	gossh "golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

func TestDecodeChunk(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		bc      *bsr.BaseChunk
		encoded []byte
		want    bsr.Chunk
	}{
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.DataChunkType,
			},
			[]byte("foo"),
			&ssh.DataChunk{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.DataChunkType,
				},
				Data: []byte("foo"),
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.BreakReqChunkType,
			},
			func() []byte {
				msg := &pssh.BreakRequest{
					RequestType:   ssh.BreakRequestType,
					WantReply:     false,
					BreakLengthMs: 43,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.BreakRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.BreakReqChunkType,
				},
				BreakRequest: &pssh.BreakRequest{
					RequestType:   ssh.BreakRequestType,
					WantReply:     false,
					BreakLengthMs: 43,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.CancelTCPIPForwardReqChunkType,
			},
			func() []byte {
				msg := &pssh.CancelTCPIPForwardRequest{
					RequestType:   ssh.CancelTCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "127.0.0.1",
					PortToBind:    87565,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.CancelTCPIPForwardRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.CancelTCPIPForwardReqChunkType,
				},
				CancelTCPIPForwardRequest: &pssh.CancelTCPIPForwardRequest{
					RequestType:   ssh.CancelTCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "127.0.0.1",
					PortToBind:    87565,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.DirectTCPIPReqChunkType,
			},
			func() []byte {
				msg := &pssh.DirectTCPIPRequest{
					RequestType:         ssh.DirectTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   60,
					MaximumPacketSize:   512,
					Host:                "127.0.0.1",
					Port:                87654,
					OriginatorIpAddress: "10.0.0.1",
					OriginatorPort:      22,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.DirectTCPIPRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.DirectTCPIPReqChunkType,
				},
				DirectTCPIPRequest: &pssh.DirectTCPIPRequest{
					RequestType:         ssh.DirectTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   60,
					MaximumPacketSize:   512,
					Host:                "127.0.0.1",
					Port:                87654,
					OriginatorIpAddress: "10.0.0.1",
					OriginatorPort:      22,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.EnvReqChunkType,
			},
			func() []byte {
				msg := &pssh.EnvRequest{
					RequestType:   ssh.EnvRequestType,
					WantReply:     false,
					VariableName:  "FOO",
					VariableValue: "bar",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.EnvRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.EnvReqChunkType,
				},
				EnvRequest: &pssh.EnvRequest{
					RequestType:   ssh.EnvRequestType,
					WantReply:     false,
					VariableName:  "FOO",
					VariableValue: "bar",
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ExecReqChunkType,
			},
			func() []byte {
				msg := &pssh.ExecRequest{
					RequestType: ssh.ExecRequestType,
					WantReply:   false,
					Command:     "/bin/run-all-the-things.sh",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ExecRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ExecReqChunkType,
				},
				ExecRequest: &pssh.ExecRequest{
					RequestType: ssh.ExecRequestType,
					WantReply:   false,
					Command:     "/bin/run-all-the-things.sh",
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ExitSignalReqChunkType,
			},
			func() []byte {
				msg := &pssh.ExitSignalRequest{
					RequestType:  ssh.ExitSignalRequestType,
					WantReply:    false,
					SignalName:   "HUP",
					CoreDumped:   false,
					ErrorMessage: "Failed Release",
					LanguageTag:  "en-US",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ExitSignalRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ExitSignalReqChunkType,
				},
				ExitSignalRequest: &pssh.ExitSignalRequest{
					RequestType:  ssh.ExitSignalRequestType,
					WantReply:    false,
					SignalName:   "HUP",
					CoreDumped:   false,
					ErrorMessage: "Failed Release",
					LanguageTag:  "en-US",
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ExitStatusReqChunkType,
			},
			func() []byte {
				msg := &pssh.ExitStatusRequest{
					RequestType: ssh.ExitStatusRequestType,
					WantReply:   false,
					ExitStatus:  34,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ExitStatusRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ExitStatusReqChunkType,
				},
				ExitStatusRequest: &pssh.ExitStatusRequest{
					RequestType: ssh.ExitStatusRequestType,
					WantReply:   false,
					ExitStatus:  34,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ForwardedTCPIPReqChunkType,
			},
			func() []byte {
				msg := &pssh.ForwardedTCPIPRequest{
					RequestType:         ssh.ForwardedTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   70,
					MaximumPacketSize:   1024,
					Address:             "10.0.0.45",
					Port:                2222,
					OriginatorIpAddress: "127.0.0.1",
					OriginatorPort:      8765,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ForwardedTCPIPRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ForwardedTCPIPReqChunkType,
				},
				ForwardedTCPIPRequest: &pssh.ForwardedTCPIPRequest{
					RequestType:         ssh.ForwardedTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   70,
					MaximumPacketSize:   1024,
					Address:             "10.0.0.45",
					Port:                2222,
					OriginatorIpAddress: "127.0.0.1",
					OriginatorPort:      8765,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.PtyReqChunkType,
			},
			func() []byte {
				msg := &pssh.PtyRequest{
					RequestType:             ssh.PtyRequestType,
					WantReply:               false,
					TermEnvVar:              "xterm",
					TerminalWidthCharacters: 80,
					TerminalHeightRows:      60,
					TerminalWidthPixels:     960,
					TerminalHeightPixels:    1080,
					EncodedTerminalMode: func() []byte {
						var tm []byte
						modes := []struct {
							Key byte
							Val uint32
						}{
							{gossh.ECHO, 0},              // disable echoing
							{gossh.TTY_OP_ISPEED, 14400}, // input speed = 14.4kbaud
							{gossh.TTY_OP_OSPEED, 14400}, // output speed = 14.4kbaud
						}
						for _, m := range modes {
							tm = append(tm, gossh.Marshal(&m)...)
						}
						return tm
					}(),
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.PtyRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.PtyReqChunkType,
				},
				PtyRequest: &pssh.PtyRequest{
					RequestType:             ssh.PtyRequestType,
					WantReply:               false,
					TermEnvVar:              "xterm",
					TerminalWidthCharacters: 80,
					TerminalHeightRows:      60,
					TerminalWidthPixels:     960,
					TerminalHeightPixels:    1080,
					EncodedTerminalMode: func() []byte {
						var tm []byte
						modes := []struct {
							Key byte
							Val uint32
						}{
							{gossh.ECHO, 0},              // disable echoing
							{gossh.TTY_OP_ISPEED, 14400}, // input speed = 14.4kbaud
							{gossh.TTY_OP_OSPEED, 14400}, // output speed = 14.4kbaud
						}
						for _, m := range modes {
							tm = append(tm, gossh.Marshal(&m)...)
						}
						return tm
					}(),
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.SessionReqChunkType,
			},
			func() []byte {
				msg := &pssh.SessionRequest{
					RequestType:       ssh.SessionRequestType,
					SenderChannel:     5,
					InitialWindowSize: 60,
					MaximumPacketSize: 512,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.SessionRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.SessionReqChunkType,
				},
				SessionRequest: &pssh.SessionRequest{
					RequestType:       ssh.SessionRequestType,
					SenderChannel:     5,
					InitialWindowSize: 60,
					MaximumPacketSize: 512,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ShellReqChunkType,
			},
			func() []byte {
				msg := &pssh.ShellRequest{
					RequestType: ssh.ShellRequestType,
					WantReply:   false,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ShellRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ShellReqChunkType,
				},
				ShellRequest: &pssh.ShellRequest{
					RequestType: ssh.ShellRequestType,
					WantReply:   false,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.SignalReqChunkType,
			},
			func() []byte {
				msg := &pssh.SignalRequest{
					RequestType: ssh.SignalRequestType,
					WantReply:   false,
					SignalName:  "USR1",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.SignalRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.SignalReqChunkType,
				},
				SignalRequest: &pssh.SignalRequest{
					RequestType: ssh.SignalRequestType,
					WantReply:   false,
					SignalName:  "USR1",
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.SubsystemReqChunkType,
			},
			func() []byte {
				msg := &pssh.SubsystemRequest{
					RequestType:   ssh.SubsystemRequestType,
					WantReply:     false,
					SubsystemName: "sftp",
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.SubsystemRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.SubsystemReqChunkType,
				},
				SubsystemRequest: &pssh.SubsystemRequest{
					RequestType:   ssh.SubsystemRequestType,
					WantReply:     false,
					SubsystemName: "sftp",
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.TCPIPForwardReqChunkType,
			},
			func() []byte {
				msg := &pssh.TCPIPForwardRequest{
					RequestType:   ssh.TCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "127.0.0.1",
					PortToBind:    2222,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.TCPIPForwardRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.TCPIPForwardReqChunkType,
				},
				TCPIPForwardRequest: &pssh.TCPIPForwardRequest{
					RequestType:   ssh.TCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "127.0.0.1",
					PortToBind:    2222,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.WindowChangeReqChunkType,
			},
			func() []byte {
				msg := &pssh.WindowChangeRequest{
					RequestType:          ssh.WindowChangeRequestType,
					WantReply:            false,
					TerminalWidthColumns: 120,
					TerminalHeightRows:   120,
					TerminalWidthPixels:  1920,
					TerminalHeightPixels: 1080,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.WindowChangeRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.WindowChangeReqChunkType,
				},
				WindowChangeRequest: &pssh.WindowChangeRequest{
					RequestType:          ssh.WindowChangeRequestType,
					WantReply:            false,
					TerminalWidthColumns: 120,
					TerminalHeightRows:   120,
					TerminalWidthPixels:  1920,
					TerminalHeightPixels: 1080,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.X11ForwardingReqChunkType,
			},
			func() []byte {
				msg := &pssh.X11ForwardingRequest{
					RequestType:               ssh.X11ForwardingRequestType,
					WantReply:                 false,
					SingleConnection:          true,
					X11AuthenticationProtocol: "MIT-MAGIC-COOKIE-1",
					X11AuthenticationCookie:   "6D6167696320636F6F6B6965",
					X11ScreenNumber:           10,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.X11ForwardingRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.X11ForwardingReqChunkType,
				},
				X11ForwardingRequest: &pssh.X11ForwardingRequest{
					RequestType:               ssh.X11ForwardingRequestType,
					WantReply:                 false,
					SingleConnection:          true,
					X11AuthenticationProtocol: "MIT-MAGIC-COOKIE-1",
					X11AuthenticationCookie:   "6D6167696320636F6F6B6965",
					X11ScreenNumber:           10,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.X11ReqChunkType,
			},
			func() []byte {
				msg := &pssh.X11Request{
					RequestType:       ssh.X11RequestType,
					SenderChannel:     6,
					InitialWindowSize: 40,
					MaximumPacketSize: 512,
					OriginatorAddress: "127.0.0.1",
					OriginatorPort:    2222,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.X11Request{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.X11ReqChunkType,
				},
				X11Request: &pssh.X11Request{
					RequestType:       ssh.X11RequestType,
					SenderChannel:     6,
					InitialWindowSize: 40,
					MaximumPacketSize: 512,
					OriginatorAddress: "127.0.0.1",
					OriginatorPort:    2222,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.XonXoffReqChunkType,
			},
			func() []byte {
				msg := &pssh.XonXoffRequest{
					RequestType: ssh.X11RequestType,
					WantReply:   false,
					ClientCanDo: true,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.XonXoffRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.XonXoffReqChunkType,
				},
				XonXoffRequest: &pssh.XonXoffRequest{
					RequestType: ssh.X11RequestType,
					WantReply:   false,
					ClientCanDo: true,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.UnknownReqChunkType,
			},
			func() []byte {
				msg := &pssh.UnknownRequest{
					RequestType: "unknown",
					WantReply:   false,
					Data:        []byte("foo"),
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.UnknownRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.UnknownReqChunkType,
				},
				UnknownRequest: &pssh.UnknownRequest{
					RequestType: "unknown",
					WantReply:   false,
					Data:        []byte("foo"),
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.CancelTCPIPForwardReqChunkType,
			},
			func() []byte {
				msg := &pssh.CancelTCPIPForwardRequest{
					RequestType:   ssh.CancelTCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "::1",
					PortToBind:    87565,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.CancelTCPIPForwardRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.CancelTCPIPForwardReqChunkType,
				},
				CancelTCPIPForwardRequest: &pssh.CancelTCPIPForwardRequest{
					RequestType:   ssh.CancelTCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "::1",
					PortToBind:    87565,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.DirectTCPIPReqChunkType,
			},
			func() []byte {
				msg := &pssh.DirectTCPIPRequest{
					RequestType:         ssh.DirectTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   60,
					MaximumPacketSize:   512,
					Host:                "::1",
					Port:                87654,
					OriginatorIpAddress: "10.0.0.1",
					OriginatorPort:      22,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.DirectTCPIPRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.DirectTCPIPReqChunkType,
				},
				DirectTCPIPRequest: &pssh.DirectTCPIPRequest{
					RequestType:         ssh.DirectTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   60,
					MaximumPacketSize:   512,
					Host:                "::1",
					Port:                87654,
					OriginatorIpAddress: "10.0.0.1",
					OriginatorPort:      22,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.ForwardedTCPIPReqChunkType,
			},
			func() []byte {
				msg := &pssh.ForwardedTCPIPRequest{
					RequestType:         ssh.ForwardedTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   70,
					MaximumPacketSize:   1024,
					Address:             "10.0.0.45",
					Port:                2222,
					OriginatorIpAddress: "::1",
					OriginatorPort:      8765,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.ForwardedTCPIPRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.ForwardedTCPIPReqChunkType,
				},
				ForwardedTCPIPRequest: &pssh.ForwardedTCPIPRequest{
					RequestType:         ssh.ForwardedTCPIPRequestType,
					SenderChannel:       5,
					InitialWindowSize:   70,
					MaximumPacketSize:   1024,
					Address:             "10.0.0.45",
					Port:                2222,
					OriginatorIpAddress: "::1",
					OriginatorPort:      8765,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.TCPIPForwardReqChunkType,
			},
			func() []byte {
				msg := &pssh.TCPIPForwardRequest{
					RequestType:   ssh.TCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "::1",
					PortToBind:    2222,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.TCPIPForwardRequest{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.TCPIPForwardReqChunkType,
				},
				TCPIPForwardRequest: &pssh.TCPIPForwardRequest{
					RequestType:   ssh.TCPIPForwardRequestType,
					WantReply:     false,
					AddressToBind: "::1",
					PortToBind:    2222,
				},
			},
		},
		{
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.X11ReqChunkType,
			},
			func() []byte {
				msg := &pssh.X11Request{
					RequestType:       ssh.X11RequestType,
					SenderChannel:     6,
					InitialWindowSize: 40,
					MaximumPacketSize: 512,
					OriginatorAddress: "::1",
					OriginatorPort:    2222,
				}
				data, err := proto.Marshal(msg)
				require.NoError(t, err)
				return data
			}(),
			&ssh.X11Request{
				BaseChunk: &bsr.BaseChunk{
					Protocol: ssh.Protocol,
					Type:     ssh.X11ReqChunkType,
				},
				X11Request: &pssh.X11Request{
					RequestType:       ssh.X11RequestType,
					SenderChannel:     6,
					InitialWindowSize: 40,
					MaximumPacketSize: 512,
					OriginatorAddress: "::1",
					OriginatorPort:    2222,
				},
			},
		},
	}

	for _, tc := range cases {
		t.Run(string(tc.bc.Type), func(t *testing.T) {
			got, err := ssh.DecodeChunk(ctx, tc.bc, tc.encoded)
			require.NoError(t, err)

			assert.Empty(t,
				cmp.Diff(
					got, tc.want,
					cmpopts.IgnoreUnexported(
						bsr.BaseChunk{},
						pssh.BreakRequest{},
						pssh.CancelTCPIPForwardRequest{},
						pssh.DirectTCPIPRequest{},
						pssh.EnvRequest{},
						pssh.ExecRequest{},
						pssh.ExitSignalRequest{},
						pssh.ExitStatusRequest{},
						pssh.ForwardedTCPIPRequest{},
						pssh.PtyRequest{},
						pssh.SessionRequest{},
						pssh.ShellRequest{},
						pssh.SignalRequest{},
						pssh.SubsystemRequest{},
						pssh.TCPIPForwardRequest{},
						pssh.WindowChangeRequest{},
						pssh.X11ForwardingRequest{},
						pssh.X11Request{},
						pssh.XonXoffRequest{},
						pssh.UnknownRequest{},
					),
				),
			)
		})
	}
}

func TestDecodeChunkErrors(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		bc      *bsr.BaseChunk
		encoded []byte
		want    error
	}{
		{
			"not-ssh-protocol",
			&bsr.BaseChunk{
				Protocol: "TEST",
				Type:     ssh.DataChunkType,
			},
			[]byte("foo"),
			errors.New("ssh.DecodeChunk: invalid protocol TEST"),
		},
		{
			"unsupported-chunk-type",
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     "TEST",
			},
			[]byte("foo"),
			errors.New("ssh.DecodeChunk: unsupported chunk type TEST"),
		},
		{
			"nil-base-chunk",
			nil,
			[]byte("foo"),
			errors.New("ssh.DecodeChunk: nil base chunk: invalid parameter"),
		},
		{
			"no-data",
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.BreakReqChunkType,
			},
			[]byte(""),
			errors.New("ssh.DecodeChunk: not enough data"),
		},
		{
			"invalid-data",
			&bsr.BaseChunk{
				Protocol: ssh.Protocol,
				Type:     ssh.BreakReqChunkType,
			},
			[]byte("foo"),
			errors.New("cannot parse invalid wire-format data"),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ssh.DecodeChunk(ctx, tc.bc, tc.encoded)
			require.ErrorContains(t, err, tc.want.Error())
		})
	}
}
