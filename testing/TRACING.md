# Tracing in Boundary

Boundary includes a small number of runtime tracing user regions, which can be used to see where Boundary spends its time during execution.
To create a trace, we first need to expose the pprof endpoint. It is disabled by default. Exposing the pprof endpoint is as simple as importing the correct package anywhere in Boundary:

```go
package anything

import (
    _ "net/http/pprof"
)
```

This will create a new HTTP endpoint on `localhost:6060` of the running binary. As such, it's only accessible to the users on the same machine.
Remember to remove this import again once you're done testing.

To create a trace, one can use any tool that allows creating HTTP requests, e.g. `curl`. To create a 3 second trace:

```
$ curl -o trace.out http://localhost:6060/debug/pprof/trace?seconds=3
```

Traces are most interesting if they contain some request handling, so it is recommended to prepare some HTTP requests that trigger the behavior you want to understand that you can run while the trace is being collected.

Once you have a trace, you can view it using the `gotraceui` tool. See https://github.com/dominikh/gotraceui/ for installation instructions,
but for both Windows and Mac it's as simple as:

```
$ go run honnef.co/go/gotraceui/cmd/gotraceui@master trace.out
```

