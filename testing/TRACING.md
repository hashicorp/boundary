# Tracing in Boundary

Boundary includes a small number of runtime tracing user regions, which can be used to see where Boundary spends its time during execution.
To create a trace, we first need to expose the pprof endpoint. It is disabled by default. Exposing the pprof endpoint requires enabling the runtime `-debug` flag on a process with an `ops` listener.

```
make build
boundary dev -debug -ops-listen-address=127.0.0.1:9203
```

This will expose the pprof endpoints on the configured ops listener. With the example above, that means `127.0.0.1:9203`, so it's only accessible to users on the same machine.

To create a trace, one can use any tool that allows creating HTTP requests, e.g. `curl`. To create a 3 second trace:

```
$ curl -o trace.out http://127.0.0.1:9203/debug/pprof/trace?seconds=3
```

Traces are most interesting if they contain some request handling, so it is recommended to prepare some HTTP requests that trigger the behavior you want to understand that you can run while the trace is being collected.

Once you have a trace, you can view it using the `gotraceui` tool. See https://github.com/dominikh/gotraceui/ for installation instructions,
but for both Windows and Mac it's as simple as:

```
$ go run honnef.co/go/gotraceui/cmd/gotraceui@master trace.out
```

