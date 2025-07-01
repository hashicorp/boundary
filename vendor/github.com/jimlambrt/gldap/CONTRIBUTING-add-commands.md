# Adding a new command (msg/request)

At a very high-level, what does it take to add new command (msg/request) to
gldap. 

- Define new request and message type (message.go)
  - define new `requestType`
  - define new msg type (see `SimpleBindMessage` as an example) Perhaps move msg
    type into it's own file like add.go
  - Add support for the new message type in `newMessage(...)` (message.go) 
    - add case to `switch reqType {}` for new msg type


- Add support for the new msg/request type for a `packet`
  - Add support for the new request type in `packet.requestType()` 
  - Define a new receiver func on `packet` that retrieves appropriate parameter
    data from the ber packet to build the msg type from the inbound packet. see
    `addParameters(..)`  as an example of how-to


- Support new msg/request type in an inbound request:
  - Add support for new msg type in `newRequest(...)` (request.go) see: `switch v := m.(type) {}` 
    - Add `Request` receiver func for getting the new msg type from the request.
      See `GetAddMessage(...)` as an example


- Support responses for the new msg/request type
  - Optionally define new response type (response.go).  See `BindResponse` as an
    example.  This is optional because we may be able to reuse the
    `GeneralResponse` for the new response... check before adding a new response
    type. 
    - includes defining receiver funcs like `packet(...)` for the new response
      type. 
    - Add support in `Request` (request.go) for the new response type
      - Create a response from the inbound request.  See `NewBindResponse(...) `
      - Get the new msg from the inbound `Request`.  See `GetModifyMessage()`
   

- Support routing the new msg/request to a handler
  - Add new route type (route.go) for new command.  See `addRoute` type as an example
  - define new `routeOperation`
  - define new route that includes a `baseRoute` 
    - implement `match(...)` for new route type
  - Add new receiver func to `Mux` to support routing of new command

- Add support for a test packet for the new msg/request. See `testModifyRequestPacket(...)`
  
- Add support in testdirectory for the new msg/request

- Required tests
  - e2e tests
  - testdirectory
  - Test_newRequest
    - add tests that use the new msg type (positive and negative tests)


- Update README 
  - testdirectory
  - gldap