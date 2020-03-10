// Package any provides  a Queue (FIFO) of any structure. The Queue uses a 
// []byte as it's buffer, so it's easy to send the queue across a wire, or 
// store it anywhere handy (file, RDBMS, Redis, basically anywhere you can store bytes).
package any
