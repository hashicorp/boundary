// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/servers/services"
	"github.com/hashicorp/nodeenrollment"
	"github.com/hashicorp/nodeenrollment/registration"
	"github.com/hashicorp/nodeenrollment/rotation"
	nodeefile "github.com/hashicorp/nodeenrollment/storage/file"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
)

func Test_RegisterUpstreamMessageHandler(t *testing.T) {
	// IMPORTANT: cannot run with t.Parallel() because it operates on the
	// handlers pkg state.
	testCtx := context.Background()
	tests := []struct {
		name                         string
		msgType                      pbs.MsgType
		h                            UpstreamMessageHandler
		withUpstreamMsgTypeSpecifier bool
		wantErr                      bool
		wantErrMatch                 *errors.Template
		wantErrContains              string
	}{
		{
			name:            "missing-msg-type",
			h:               &TestMockUpstreamMessageHandler{},
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing msg type",
		},
		{
			name:            "missing-handler",
			msgType:         pbs.MsgType_MSG_TYPE_ECHO,
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing handler",
		},
		{
			name:    "success",
			msgType: pbs.MsgType_MSG_TYPE_ECHO,
			h:       &TestMockUpstreamMessageHandler{},
		},
		{
			name:                         "success-with-type-specifier",
			msgType:                      pbs.MsgType_MSG_TYPE_ECHO,
			h:                            &TestMockUpstreamMessageHandler{},
			withUpstreamMsgTypeSpecifier: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			cp := new(sync.Map)
			upstreamMessageHandler.Range(func(k, v interface{}) bool {
				cp.Store(k, v)
				return true
			})
			err := RegisterUpstreamMessageHandler(testCtx, tc.msgType, tc.h)
			t.Cleanup(func() {
				upstreamMessageHandler = cp
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "unexpected error: %q", err.Error())
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			_, ok := getUpstreamMessageHandler(testCtx, tc.msgType)
			assert.True(ok)

			if tc.withUpstreamMsgTypeSpecifier {
				_, ok := getUpstreamMessageTypeSpecifier(testCtx, tc.msgType)
				assert.True(ok)
			}
		})
	}
}

func Test_controllerUpstreamMessageServiceServer_UpstreamMessage(t *testing.T) {
	// IMPORTANT: cannot run with t.Parallel() because it operates on the
	// handlers pkg state.

	testCtx := context.Background()

	// Get an initial set of authorized node credentials
	initStorage, err := nodeefile.New(testCtx)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, initStorage.Cleanup(testCtx)) })
	_, err = rotation.RotateRootCertificates(testCtx, initStorage)
	require.NoError(t, err)
	initNodeCreds, err := types.NewNodeCredentials(testCtx, initStorage)
	require.NoError(t, err)
	req, err := initNodeCreds.CreateFetchNodeCredentialsRequest(testCtx)
	require.NoError(t, err)
	_, err = registration.AuthorizeNode(testCtx, initStorage, req)
	require.NoError(t, err)
	fetchResp, err := registration.FetchNodeCredentials(testCtx, initStorage, req)
	require.NoError(t, err)
	initNodeCreds, err = initNodeCreds.HandleFetchNodeCredentialsResponse(testCtx, initStorage, fetchResp)
	require.NoError(t, err)
	initKeyId, err := nodeenrollment.KeyIdFromPkix(initNodeCreds.CertificatePublicKeyPkix)
	require.NoError(t, err)
	nodeInfo, err := types.LoadNodeInformation(testCtx, initStorage, initKeyId)
	require.NoError(t, err)
	// define a test controller
	testController, err := NewControllerUpstreamMessageServiceServer(testCtx, initStorage)
	require.NoError(t, err)
	require.NotNil(t, testController)

	tests := []struct {
		name             string
		controllerServer pbs.UpstreamMessageServiceServer
		setupHandlers    func(t *testing.T)
		req              *pbs.UpstreamMessageRequest
		wantErr          bool
		wantErrContains  string
	}{
		{
			name:             "success-echo-unencrypted",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					pt, err := proto.Marshal(&pbs.EchoUpstreamMessageRequest{Msg: "ping"})
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Pt{Pt: pt}
				}(),
			},
			setupHandlers: TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockUpstreamMessageHandler{}),
		},
		{
			name:             "unimplemented",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_UNSPECIFIED,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					return &pbs.UpstreamMessageRequest_Pt{Pt: []byte("Unimplemented.")}
				}(),
			},
			wantErr:         true,
			wantErrContains: "msg type \"MSG_TYPE_UNSPECIFIED\" is unsupported",
		},
		{
			name:             "missing-originating-worker-id",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				MsgType: pbs.MsgType_MSG_TYPE_ECHO,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					pt, err := proto.Marshal(&pbs.EchoUpstreamMessageRequest{Msg: "ping"})
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Pt{Pt: pt}
				}(),
			},
			wantErr:         true,
			wantErrContains: "missing originating worker id",
		},
		{
			name:             "unsupported-msg-type",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_UNSPECIFIED,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					pt, err := proto.Marshal(&pbs.EchoUpstreamMessageRequest{Msg: "ping"})
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Pt{Pt: pt}
				}(),
			},
			wantErr:         true,
			wantErrContains: "msg type \"MSG_TYPE_UNSPECIFIED\" is unsupported",
		},
		{
			name:             "invalid-originating-worker-id",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: "bad-id",
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message: func() *pbs.UpstreamMessageRequest_Ct {
					r := &pbs.EchoUpstreamMessageRequest{Msg: "ping"}
					ct, err := nodeenrollment.EncryptMessage(testCtx, r, nodeInfo)
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Ct{Ct: ct}
				}(),
			},
			setupHandlers:   TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockEncryptedUpstreamMessageHandler{}),
			wantErr:         true,
			wantErrContains: "error loading node information",
		},
		{
			name:             "invalid-unencrypted-msg",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message:                &pbs.UpstreamMessageRequest_Pt{Pt: []byte("not-a-proto")},
			},
			setupHandlers:   TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockUpstreamMessageHandler{}),
			wantErr:         true,
			wantErrContains: "error marshaling request message",
		},
		{
			name:             "invalid-encrypted-msg",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message:                &pbs.UpstreamMessageRequest_Ct{Ct: []byte("not-an-encrypted-proto")},
			},
			setupHandlers:   TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockEncryptedUpstreamMessageHandler{}),
			wantErr:         true,
			wantErrContains: "error decrypting request message",
		},
		{
			name:             "message-handler-not-implemented",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                -1,
				Message:                &pbs.UpstreamMessageRequest_Ct{Ct: []byte("not-an-encrypted-proto")},
			},
			wantErr:         true,
			wantErrContains: "Unimplemented desc = upstream message handler for \"-1\" is not implemented",
		},
		{
			name:             "success-echo-unencrypted",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					pt, err := proto.Marshal(&pbs.EchoUpstreamMessageRequest{Msg: "ping"})
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Pt{Pt: pt}
				}(),
			},
			// intentionally, no setupHandlers
			wantErr:         true,
			wantErrContains: "upstream message handler for \"MSG_TYPE_ECHO\" is not implemented",
		},
		{
			name:             "fail-echo-unencrypted",
			controllerServer: testController,
			req: &pbs.UpstreamMessageRequest{
				OriginatingWorkerKeyId: initKeyId,
				MsgType:                pbs.MsgType_MSG_TYPE_ECHO,
				Message: func() *pbs.UpstreamMessageRequest_Pt {
					pt, err := proto.Marshal(&pbs.EchoUpstreamMessageRequest{Msg: "ping"})
					require.NoError(t, err)
					return &pbs.UpstreamMessageRequest_Pt{Pt: pt}
				}(),
			},
			setupHandlers:   TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockUpstreamMessageHandler{WantHandlerErr: fmt.Errorf("fail-echo-unencrypted")}),
			wantErr:         true,
			wantErrContains: "rpc error: code = Unknown desc = fail-echo-unencrypted",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			controllerClient := pbs.NewUpstreamMessageServiceClient(grpcCCToServer(t, testCtx, tc.controllerServer))
			if tc.setupHandlers != nil {
				tc.setupHandlers(t)
			}

			gotResp, err := controllerClient.UpstreamMessage(testCtx, tc.req)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(gotResp)
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(gotResp)
		})
	}
}

func Test_SendUpstreamMessage(t *testing.T) {
	// IMPORTANT: cannot run with t.Parallel() because it operates on the
	// handlers pkg state.
	testCtx := context.Background()
	workerClientProducer, workerNodeInfo, originatingWorkerId := TestUpstreamService(t)
	testHandler := &TestMockUpstreamMessageHandler{}
	testEncryptedHandler := &TestMockEncryptedUpstreamMessageHandler{}

	tests := []struct {
		name                string
		setupHandlers       func(t *testing.T)
		clientProducer      UpstreamMessageServiceClientProducer
		originatingWorkerId string
		req                 proto.Message
		opt                 []Option
		wantResp            proto.Message
		wantErr             bool
		wantErrContains     string
	}{
		{
			name:                "success-echo-unencrypted",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			wantResp:            &pbs.EchoUpstreamMessageResponse{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
		},
		{
			name:                "success-echo-encrypted",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			opt:                 []Option{WithKeyProducer(workerNodeInfo)},
			wantResp:            &pbs.EchoUpstreamMessageResponse{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testEncryptedHandler),
		},
		{
			name:                "missing-client-producer",
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
			wantErr:             true,
			wantErrContains:     "missing client producer",
		},
		{
			name:            "missing-originating-worker-id",
			clientProducer:  workerClientProducer,
			req:             &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			setupHandlers:   TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
			wantErr:         true,
			wantErrContains: "missing originating worker key id",
		},
		{
			name:                "missing-req",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
			wantErr:             true,
			wantErrContains:     "missing message",
		},
		{
			name:                "invalid-msg-type",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.Connection{},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
			wantErr:             true,
			wantErrContains:     "\"\" is an unknown msg type",
		},
		{
			name:                "no-registered-handler",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			wantErr:             true,
			wantErrContains:     "upstream message handler for \"MSG_TYPE_ECHO\" is not implemented",
		},
		{
			name:                "no-registered-handler",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			wantErr:             true,
			wantErrContains:     "upstream message handler for \"MSG_TYPE_ECHO\" is not implemented",
		},
		{
			name:                "missing-node-info",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testEncryptedHandler),
			wantErr:             true,
			wantErrContains:     "missing node information required for encrypting unwrap keys message",
		},
		{
			name: "client-producer-err",
			clientProducer: func(context.Context) (pbs.UpstreamMessageServiceClient, error) {
				return nil, fmt.Errorf("client-producer-err")
			},
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, testHandler),
			wantErr:             true,
			wantErrContains:     "error getting a client producer",
		},
		{
			name:                "upstream-err",
			clientProducer:      workerClientProducer,
			originatingWorkerId: originatingWorkerId,
			req:                 &pbs.EchoUpstreamMessageRequest{Msg: "ping"},
			setupHandlers:       TestRegisterHandlerFn(t, pbs.MsgType_MSG_TYPE_ECHO, &TestMockUpstreamMessageHandler{WantHandlerErr: fmt.Errorf("upstream-err")}),
			wantErr:             true,
			wantErrContains:     "error from upstream client",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			if tc.setupHandlers != nil {
				tc.setupHandlers(t)
			}
			gotResp, err := SendUpstreamMessage(testCtx, tc.clientProducer, tc.originatingWorkerId, tc.req, tc.opt...)
			if tc.wantErr {
				require.Error(err)
				assert.Nil(gotResp)
				assert.Contains(err.Error(), tc.wantErrContains)
				return
			}
			require.NoError(err)
			require.NotNil(gotResp)
			assert.Empty(cmp.Diff(gotResp, tc.wantResp, protocmp.Transform()))
		})
	}
}

func Test_RegisterUpstreamMessageTypeSpecifier(t *testing.T) {
	// IMPORTANT: cannot run with t.Parallel() because it operates on the
	// handlers pkg state.
	testCtx := context.Background()
	tests := []struct {
		name            string
		msgType         pbs.MsgType
		s               UpstreamMessageTypeSpecifier
		wantErr         bool
		wantErrMatch    *errors.Template
		wantErrContains string
	}{
		{
			name:            "missing-msg-type",
			s:               &TestMockUpstreamMessageHandler{},
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing msg type",
		},
		{
			name:            "missing-type-specifier",
			msgType:         pbs.MsgType_MSG_TYPE_ECHO,
			wantErr:         true,
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing type specifier",
		},
		{
			name:    "success",
			msgType: pbs.MsgType_MSG_TYPE_ECHO,
			s:       &TestMockUpstreamMessageHandler{},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			cp := new(sync.Map)
			upstreamMessageTypeSpecifier.Range(func(k, v interface{}) bool {
				cp.Store(k, v)
				return true
			})
			err := registerUpstreamMessageTypeSpecifier(testCtx, tc.msgType, tc.s)
			t.Cleanup(func() {
				upstreamMessageHandler = cp
			})
			if tc.wantErr {
				require.Error(err)
				if tc.wantErrMatch != nil {
					assert.Truef(errors.Match(tc.wantErrMatch, err), "unexpected error: %q", err.Error())
				}
				if tc.wantErrContains != "" {
					assert.Contains(err.Error(), tc.wantErrContains)
				}
				return
			}
			require.NoError(err)
			_, ok := getUpstreamMessageTypeSpecifier(testCtx, tc.msgType)
			assert.True(ok)
		})
	}
}
