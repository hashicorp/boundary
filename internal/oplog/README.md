# oplog 

oplog is a package for writing operation log (oplog) entries for the purpose of replication and verification of the data stored in the Watchtower RDBMS. 

- [oplog](#oplog)
  - [Usage](#usage)
  - [TBD/TODO](#tbdtodo)
  - [oplog entry](#oplog-entry)
  - [oplog tables](#oplog-tables)
  - [oplog optimistic locking using tickets](#oplog-optimistic-locking-using-tickets)
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
newLogEntry := NewEntry(
  "test-users",
  []Metadata{
    Metadata{
      Key:   "deployment",
      Value: "amex",
    },
    Metadata{
      Key:   "project",
      Value: "central-info-systems",
    },
  },
  cipherer, // wrapping.Wrapper
  ticketer,
)

// write an entry with N messages (variadic parameter) in the order they were sent to the database 
err = oplogEntry.WriteEntryWith(
    context.Background(), 
    &GormWriter{tx}, 
    ticket,
    &Message{Message: &userCreate, TypeURL: "user", OpType: OpType_CreateOp},
)
// if there's an error writing the oplog then roll EVERYTHING back
if err != nil {
    tx.Rollback()
}
// no err means you can commit all the things.
tx.Commit()
```
## TBD/TODO
We need to discuss and decide how Watchtower is going to handle the following oplog things:

* SQL migrations: you'll find the package's [SQL migrations](https://github.com/golang-migrate/migrate) under: ./migrations/postgres   We need to decide how Watchtower will manage migrations across the system and we will likely need to reference this package's migrations somehow.
* protobuf generation: how will Watchtower generate its protobufs.  This package currently uses ./generate.sh to build its protobuf definitions: 
  * any.proto (used by the oplog entries)
  * ./store/oplog.proto 
  * ./oplog_test/oplog_test.proto
* Snapshots: design/implementation of snapshots is still being discussed in the RFC process.  Once resolved, we'll need to implement the snapshot capability.


## oplog entry
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

## oplog tables

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

## oplog optimistic locking using tickets
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