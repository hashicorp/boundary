# oplog 

oplog is a package for writing operation log (oplog) entries for the purpose of replication and verification of the data stored in the Watchtower RDBMS. 

## Usage
```go
    userCreate := oplog_test.TestUser{
		TestUser: oplog_test.TestUser{
			Name: userName,
		},
	}
    tx := db.Begin()
    // write the user to the database
    tx.Create(&userCreate)

	ticketer := &GormTicketer{Tx: db}
    // get a ticket for writing users to the oplog
	ticket, err := ticketer.GetTicket("users")

    // create an entry for the oplog with the entry's metadata (likely the entry's Scope)
	oplogEntry := Entry{
		Entry: &store.Entry{
			AggregateName: "test-users",
			Metadata: []*store.Metadata{
				&store.Metadata{
					Key:   "org",
					Value: "amex",
				},
				&store.Metadata{
					Key:   "project",
					Value: "central-info-systems",
				},
			},
		},
		Cipherer: cipherer, // a wrapping.Wrapper
		Ticketer: ticketer, 
	}

    // write an entry with N messages (variadic parameter) in the order they were sent to the database 
	err = oplogEntry.WriteEntryWith(
        context.Background(), 
        &GormWriter{tx}, 
        ticket,
        &Message{Message: &userCreate, TypeURL: "user", OpType: any.OpType_CreateOp},
    )
    // if there's an error writing the oplog then roll EVERYTHING back
    if err != nil {
        tx.Rollback()
    }
    // no err means you can commit all the things.
    tx.Commit()

```
## TBD
* SQL migrations: you'll find the package's [SQL migrations](https://github.com/golang-migrate/migrate) under: ./migrations/postgres   We need to decide how Watchtower will manage migrations across the system and we will likely need to reference this package's migrations somehow.
* protobuf generation: how will Watchtower generate its protobufs.  This package currently uses ./generate.sh to build its protobuf definitions: 
  * ./store/oplog.proto 
  * ./any/any.proto
  * ./oplog_test/oplog_test.proto

## See also
```                                            
  Example Oplog Entry for the Target Aggregate      
┌────────────────────────────────────────────────┐  
│                        FIFO with []byte buffer │  
│                                                │  
│┌─Msg 4────┐┌─Msg 3────┐┌─Msg 2────┐            │  
││          ││          ││          │            │  
││  Tags    ││  Host    ││ HostSet  │            │  
││┌────────┐││┌────────┐││┌────────┐│            │  
│││        ││││        ││││        ││            │  
│││        ││││        ││││        ││            │  
│││  Tag   ││││  Host  ││││HostSet ││            │  
│││protobuf││││protobuf││││protobuf││            │  
│││        ││││        ││││        ││            │  
│││        ││││        ││││        ││            │  
││└────────┘││└────────┘││└────────┘│            │  
││┌────────┐││┌────────┐││┌────────┐│            │  
│││        ││││        ││││        ││            │  
│││typeURL ││││typeURL ││││typeURL ││            │  
│││  Tag   ││││  Host  ││││HostSet ││            │  
││└────────┘││└────────┘││└────────┘│            │  
││┌────────┐││┌────────┐││┌────────┐│            │  
│││        ││││        ││││        ││            │  
│││ OpType ││││ OpType ││││ OpType ││            │  
│││ Create ││││ Create ││││ Create ││            │  
││└────────┘││└────────┘││└────────┘│            │  
│└──────────┘└──────────┘└──────────┘            │  
└────────────────────────────────────────────────┘  
```



```                                                                                             
                  oplog tables:                   
      as the diagram shows, we can split the      
      oplog_entries into multiple tables if       
             needed for performance.              
                                                  
┌────────────────┐                                
│┌───────────────┴┐                               
││┌───────────────┴┐            ┌────────────────┐
│││ oplog_entries  │            │  oplog_ticket  │
││├────────────────┤            ├────────────────┤
│││id              │╲           │id              │
│││aggregate_name  │──┼───────┼ │aggregate_name  │
└┤│data            │╱           │version         │
 └┤                │            │                │
  └────────────────┘            └────────────────┘
          ┼                                       
          │                                       
          │                                       
          ┼                                       
         ╱│╲                                      
 ┌────────────────┐                               
 │ oplog_metadata │                               
 ├────────────────┤                               
 │id              │                               
 │entry_id        │                               
 │key             │                               
 │value           │                               
 └────────────────┘                               
 ```

 ```                                                                                         
     Alice's                        Database                                               
   transaction                                                          Bob's transaction  
                                                                                           
      │                                 │                                      │           
      │─────────BEGIN──────────────────▶│                                      │           
      │                                 │◀───────────────BEGIN─────────────────┤           
      │                     ┌───────────┴───────────┐                          │           
      │                     │   ticket version:1    │                          │           
      │                     └───────────┬───────────┘                          │           
      │       Select oplog-ticket for   │                                      │           
      ├──────────────"Target"──────────▶│        Select oplog-ticket for       │           
      │                                 │◀──────────────"Target"───────────────┤           
      │                                 │                                      │           
      │      Write to Tables in         │                                      │           
      ├───────Target Aggregate─────────▶│                                      │           
      │                                 │         Write to Tables in           │           
      │                                 │◀─────────Target Aggregate────────────┤           
      │                                 │                                      │           
      │                                 │                                      │           
      │      Update Ticket              │                                      │           
      ├────Version = 2 where───────────▶│                                      │           
      │       Version = 1     ┌─────────┴─────────┐                            │           
      │                       │ ticket version: 2 │                            │           
      │                       └─────────┬─────────┘                            │           
      │                                 │              Update Ticket           │           
      │                                 │◀───────────Version = 2 where─────────┤           
      │                                 │               Version = 1       ┌────┴──────────┐
      │                                 │                                 │ update failed │
      ├────────────Commit──────────────▶│                                 └────┬──────────┘
      │                                 │                                      │           
      │                                 │                                      │           
      │                                 │                                      │           
      │                                 │◀────────────Rollback─────────────────┤           
      │                                 │                                      │           
      │                                 │                                      │           
      ```