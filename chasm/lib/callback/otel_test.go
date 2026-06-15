package callback

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/nexus-rpc/sdk-go/nexus"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	persistencespb "go.temporal.io/server/api/persistence/v1"
	"go.temporal.io/server/chasm"
	"go.temporal.io/server/chasm/chasmtest"
	callbackspb "go.temporal.io/server/chasm/lib/callback/gen/callbackpb/v1"
	"go.temporal.io/server/common/backoff"
	"go.temporal.io/server/common/dynamicconfig"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/metrics"
	"go.temporal.io/server/common/namespace"
	"go.temporal.io/server/common/nexus/nexusrpc"
	"go.temporal.io/server/service/history/queues/common"
	"go.uber.org/mock/gomock"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// roundTripperFunc adapts a function to an http.RoundTripper so an HTTPCaller can be routed
// through the production OTEL transport in tests.
type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type outboundInvocationResult struct {
	capturedRequest *http.Request
	spans           []sdktrace.ReadOnlySpan
	err             error
}

// runOutboundInvocation drives a full outbound CHASM callback invocation, capturing the
// outgoing HTTP request and the spans recorded during the invocation.
//
// callbackHeader is stored on the commonpb.Callback and represents headers (e.g. an
// originating/source trace context) supplied when the callback was registered. When
// wrapWithOTEL is true, the HTTPCaller is routed through the same OTEL transport used in
// production so that the active trace context is injected into the outgoing request.
func runOutboundInvocation(
	t *testing.T,
	callbackHeader nexus.Header,
	wrapWithOTEL bool,
) outboundInvocationResult {
	t.Helper()
	ctrl := gomock.NewController(t)

	// Setup namespace.
	factory := namespace.NewDefaultReplicationResolverFactory()
	detail := &persistencespb.NamespaceDetail{
		Info: &persistencespb.NamespaceInfo{
			Id:   "namespace-id",
			Name: "namespace-name",
		},
		Config: &persistencespb.NamespaceConfig{},
	}
	ns, err := namespace.FromPersistentState(detail, factory(detail))
	require.NoError(t, err)

	logger := log.NewTestLogger()

	nsRegistry := namespace.NewMockRegistry(ctrl)
	nsRegistry.EXPECT().GetNamespaceByID(gomock.Any()).Return(ns, nil)

	// Record spans emitted during the invocation.
	recorder := tracetest.NewSpanRecorder()
	tracerProvider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	propagator := propagation.TraceContext{}

	// Capture the outgoing HTTP request so we can inspect its headers.
	var captured *http.Request
	var caller HTTPCaller = func(r *http.Request) (*http.Response, error) {
		captured = r
		return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
	}
	if wrapWithOTEL {
		rt := wrapTransportWithOTEL(roundTripperFunc(caller), tracerProvider, propagator)
		caller = func(r *http.Request) (*http.Response, error) {
			return rt.RoundTrip(r)
		}
	}

	handler := &invocationTaskHandler{
		config: &Config{
			RequestTimeout: dynamicconfig.GetDurationPropertyFnFilteredByDestination(time.Second),
			RetryPolicy: func() backoff.RetryPolicy {
				return backoff.NewExponentialRetryPolicy(time.Second)
			},
		},
		namespaceRegistry: nsRegistry,
		metricsHandler:    metrics.NoopMetricsHandler,
		logger:            logger,
		httpCallerProvider: func(common.NamespaceIDAndDestination) HTTPCaller {
			return caller
		},
		tracer: tracerProvider.Tracer(callbackTracerScope),
	}

	chasmRegistry := chasm.NewRegistry(logger)
	require.NoError(t, chasmRegistry.Register(&Library{InvocationTaskHandler: handler}))
	require.NoError(t, chasmRegistry.Register(&mockNexusCompletionGetterLibrary{}))

	callback := &Callback{
		CallbackState: &callbackspb.CallbackState{
			RequestId:        "request-id",
			RegistrationTime: timestamppb.New(time.Now()),
			Callback: &callbackspb.Callback{
				Variant: &callbackspb.Callback_Nexus_{
					Nexus: &callbackspb.Callback_Nexus{
						Url:    "http://localhost",
						Header: callbackHeader,
					},
				},
			},
			Status:  callbackspb.CALLBACK_STATUS_SCHEDULED,
			Attempt: 0,
		},
	}

	executionKey := chasm.ExecutionKey{
		NamespaceID: "namespace-id",
		BusinessID:  "workflow-id",
		RunID:       "run-id",
	}
	testEngine := chasmtest.NewEngine(t, chasmRegistry)
	engineCtx := chasm.NewEngineContext(context.Background(), testEngine)
	_, err = chasm.StartExecution(
		engineCtx,
		executionKey,
		func(ctx chasm.MutableContext, _ struct{}) (*mockNexusCompletionGetterComponent, error) {
			return &mockNexusCompletionGetterComponent{
				completion: nexusrpc.CompleteOperationOptions{},
				Callback:   chasm.NewComponentField(ctx, callback),
			}, nil
		},
		struct{}{},
	)
	require.NoError(t, err)

	rootRef := chasm.NewComponentRef[*mockNexusCompletionGetterComponent](executionKey)
	callbackRef, err := chasm.ReadComponent(
		engineCtx,
		rootRef,
		func(_ *mockNexusCompletionGetterComponent, chasmCtx chasm.Context, _ struct{}) (chasm.ComponentRef, error) {
			serialized, err := chasmCtx.Ref(callback)
			if err != nil {
				return chasm.ComponentRef{}, err
			}
			return chasm.DeserializeComponentRef(serialized)
		},
		struct{}{},
	)
	require.NoError(t, err)

	executeErr := handler.Execute(
		engineCtx,
		callbackRef,
		chasm.TaskAttributes{Destination: "http://localhost"},
		&callbackspb.InvocationTask{Attempt: 0},
	)

	return outboundInvocationResult{
		capturedRequest: captured,
		spans:           recorder.Ended(),
		err:             executeErr,
	}
}

func findSpan(spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	return nil
}

func spanAttributes(span sdktrace.ReadOnlySpan) map[attribute.Key]attribute.Value {
	attrs := make(map[attribute.Key]attribute.Value)
	for _, kv := range span.Attributes() {
		attrs[kv.Key] = kv.Value
	}
	return attrs
}

// TestOutboundInvocation_RecordsSpanAndInjectsTraceContext confirms that invoking an
// outbound callback starts a span describing the invocation and that the active trace
// context is propagated into the outgoing HTTP request as a W3C traceparent header.
func TestOutboundInvocation_RecordsSpanAndInjectsTraceContext(t *testing.T) {
	res := runOutboundInvocation(t, nil /* callbackHeader */, true /* wrapWithOTEL */)
	require.NoError(t, res.err)
	require.NotNil(t, res.capturedRequest)

	invocationSpan := findSpan(res.spans, "CHASMCallbackInvocation")
	require.NotNil(t, invocationSpan, "expected a CHASMCallbackInvocation span to be recorded")

	// The span should be tagged with the Temporal-specific attributes.
	attrs := spanAttributes(invocationSpan)
	require.Equal(t, "namespace-name", attrs[attrTemporalNamespace].AsString())
	require.Equal(t, "workflow-id", attrs[attrTemporalBusinessID].AsString())
	require.Equal(t, "run-id", attrs[attrTemporalRunID].AsString())
	require.Equal(t, "http://localhost", attrs[attrTemporalCallbackDestination].AsString())

	// The OTEL transport should have injected the trace context into the outgoing request.
	traceparent := res.capturedRequest.Header.Get("traceparent")
	require.NotEmpty(t, traceparent, "expected outgoing request to carry a W3C traceparent header")
	require.Contains(t, traceparent, invocationSpan.SpanContext().TraceID().String(),
		"propagated traceparent should share the invocation span's trace ID")
}

// TestOutboundInvocation_ForwardsCallbackHeaders confirms that OTEL headers supplied on the
// commonpb.Callback (e.g. capturing the originating/source span) are wired through to the
// outgoing completion request.
func TestOutboundInvocation_ForwardsCallbackHeaders(t *testing.T) {
	// A source trace context recorded on the callback at registration time.
	const sourceTraceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01"
	header := nexus.Header{
		"traceparent": sourceTraceparent,
		"baggage":     "source=upstream",
	}

	// Use the raw caller (no OTEL transport) so the callback's stored headers are forwarded
	// without being overwritten by the active trace context, isolating the forwarding logic.
	res := runOutboundInvocation(t, header, false /* wrapWithOTEL */)
	require.NoError(t, res.err)
	require.NotNil(t, res.capturedRequest)

	require.Equal(t, sourceTraceparent, res.capturedRequest.Header.Get("traceparent"),
		"callback's stored traceparent should be forwarded to the outgoing request")
	require.Equal(t, "source=upstream", res.capturedRequest.Header.Get("baggage"),
		"callback's stored baggage header should be forwarded to the outgoing request")
}
