# Boundary External Plugins Modules

The Go modules under `plugins` are not intended to be used directly. They are
here purely to allow compilation of the various plugins Boundary supports
without pulling the dependencies (and any clashes, and any init behavior)
directly into Boundary.
