# db package

## Usage
Just some high-level usage highlights to get you started.  Read the godocs for a complete list of capabilities and their documentation.

```go
    dialect = postgres.New(postgres.Config{
			DSN: connectionUrl},
		)
    conn, _ := gorm.Open(dialect, &gorm.Config{})
    
    // Db implements both the Reader and Writer interfaces
    rw := Db{Tx: conn}
    
    // There are writer methods like: Create, Update and Delete
    // that will write Gorm struct to the db.  These writer methods
    // all support options for writing Oplog entries for the 
    // caller: WithOplog(yourWrapper, yourMetadata)
    // the caller is responsible for the transaction life cycle of the writer
    // and if an error is returned the caller must decide what to do with 
    // the transaction, which is almost always a rollback for the caller.
    err = rw.Create(context.Background(), user)
   
    // There are reader methods like: LookupByPublicId,  
    // LookupByName, SearchBy, LookupBy, etc
    // which will lookup resources for you and scan them into your Gorm struct
    err = rw.LookupByPublicId(context.Background(), foundUser)

    // There's reader ScanRows that facilitates scanning rows from 
    // a query into your Gorm struct
    where := "select * from test_users where name in ($1, $2)"
    rows, err := rw.Query(context.Background(), where, []interface{}{"alice", "bob"})
	defer rows.Close()
	for rows.Next() {
        user := db_test.NewTestUser()
        // scan the row into your Gorm struct
		if err := rw.ScanRows(rows, &user); err != nil {
            return err
        }
        // Do something with the Gorm user struct
    }
    if err := rows.Err(); err != nil {
        // do something with the err
    }

    // DoTx is a writer function that wraps a TxHandler 
    // in a retryable transaction.  You simply implement a
    // TxHandler that does your writes and hand the handler
    // to DoTx, which will wrap the writes in a retryable 
    // transaction with the retry attempts and backoff
    // strategy you specify via options.
    _, err = w.DoTx(
        context.Background(),
        10,           // ten retries
        ExpBackoff{}, // exponential backoff
        func(w Writer) error {
            // the TxHandler updates the user's friendly name
            return w.Update(context.Background(), user, []string{"FriendlyName"},
                // write oplogs for this update
                WithOplog(
                    InitTestWrapper(t),
                    oplog.Metadata{
                        "key-only":   nil,
                        "deployment": []string{"amex"},
                        "project":    []string{"central-info-systems", "local-info-systems"},
                    },
                ),
            )
        })


```
