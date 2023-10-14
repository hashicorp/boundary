// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package pagination_test

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/boundary/internal/boundary"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/refreshtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
)

// An example resource. In a real example, this would
// be a Target or Session or similar.
type ExampleResource struct {
	boundary.Resource
	Value int
}

func (e *ExampleResource) GetPublicId() string {
	return "er_1234567890"
}

func (e *ExampleResource) GetUpdateTime() *timestamp.Timestamp {
	return timestamp.New(time.Now().Add(-10 * time.Hour))
}

func (e *ExampleResource) GetResourceType() resource.Type {
	return resource.Unknown
}

func ExampleList() {
	grantsHash := []byte("hash-of-grants") // Acquired from authorization logic
	pageSize := 10                         // From request or service default
	filterItemFunc := func(ctx context.Context, item *ExampleResource) (bool, error) {
		// Inspect item to determine whether we want to
		// include it in the final list.
		return item.Value < 5, nil
	}
	listItemsFunc := func(ctx context.Context, prevPageLast *ExampleResource, limit int) ([]*ExampleResource, error) {
		// Do the listing of the resource, generally using a
		// repository method such as target.(*Repository).listTargets.
		// Use the input to set up any options, for example a limit
		// or a starting point.
		if prevPageLast == nil {
			// No previous page item means this is the first list request.
			// List using limit.
			// opts := target.Option{
			//	target.WithLimit(limit),
			// }
		} else {
			// Use the previous page last item to start pagination from the
			// next page.
			// opts := target.Option{
			//	target.WithLimit(limit),
			//	target.WithStartPageAfterItem(prevPageLast.GetPublicId(), prevPageLast.GetUpdateTime()),
			// }
		}
		// Example result from the repository
		return []*ExampleResource{
			{nil, 0},
			{nil, 1},
			{nil, 2},
			{nil, 3},
			{nil, 4},
			{nil, 5},
			{nil, 6},
			{nil, 7},
			{nil, 8},
			{nil, 9},
			{nil, 10},
		}, nil
	}
	estimatedCountFunc := func(ctx context.Context) (int, error) {
		// Get an estimate from the database of the total number
		// of entries for this resource, usually using some
		// repository method.
		return 1000, nil
	}
	resp, err := pagination.List(context.Background(), grantsHash, pageSize, filterItemFunc, listItemsFunc, estimatedCountFunc)
	if err != nil {
		fmt.Println("failed to paginate", err)
		return
	}
	fmt.Println("Got results:")
	for _, item := range resp.Items {
		fmt.Printf("\tValue: %d\n", item.Value)
	}
	if resp.CompleteListing {
		fmt.Println("Listing was complete")
	} else {
		fmt.Println("Listing was not complete")
	}
	fmt.Println("There are an estimated", resp.EstimatedItemCount, "total items available")
	// Output: Got results:
	//	Value: 0
	//	Value: 1
	//	Value: 2
	//	Value: 3
	//	Value: 4
	//	Value: 0
	//	Value: 1
	//	Value: 2
	//	Value: 3
	//	Value: 4
	// Listing was not complete
	// There are an estimated 1000 total items available
}

func ExampleListRefresh() {
	grantsHash := []byte("hash-of-grants") // Acquired from authorization logic
	pageSize := 10                         // From request or service default
	refreshToken, err := refreshtoken.New( // Normally from incoming request
		context.Background(),
		time.Now(),
		time.Now(),
		resource.Unknown,
		grantsHash,
		"er_1234567890",
		time.Now().Add(-time.Hour),
	)
	if err != nil {
		fmt.Println("failed to paginate", err)
		return
	}
	filterItemFunc := func(ctx context.Context, item *ExampleResource) (bool, error) {
		// Inspect item to determine whether we want to
		// include it in the final list.
		return item.Value < 5, nil
	}
	listItemsFunc := func(ctx context.Context, tok *refreshtoken.Token, prevPageLast *ExampleResource, limit int) ([]*ExampleResource, error) {
		// Do the listing of the resource, generally using a
		// repository method such as target.(*Repository).listTargets.
		// Use the input to set up any options, for example a limit
		// or a starting point.
		if prevPageLast == nil {
			// No previous page item means use the values from the refresh token.
			// opts := target.Option{
			//	target.WithLimit(limit),
			//	target.WithStartPageAfterItem(tok.GetPublicId(), tok.GetUpdateTime()),
			// }
		} else {
			// Use the previous page last item to start pagination from the next page.
			// opts := target.Option{
			//	target.WithLimit(limit),
			//	target.WithStartPageAfterItem(prevPageLast.GetPublicId(), prevPageLast.GetUpdateTime()),
			// }
		}
		// Example result from the repository
		return []*ExampleResource{
			{nil, 0},
			{nil, 1},
			{nil, 2},
			{nil, 3},
			{nil, 4},
			{nil, 5},
			{nil, 6},
			{nil, 7},
			{nil, 8},
			{nil, 9},
			{nil, 10},
		}, nil
	}
	estimatedCountFunc := func(ctx context.Context) (int, error) {
		// Get an estimate from the database of the total number
		// of entries for this resource, usually using some
		// repository method.
		return 1000, nil
	}
	deletedIdsFunc := func(ctx context.Context, since time.Time) ([]string, time.Time, error) {
		// Return IDs of resources that have been deleted since the provided timestamp.
		// Also return a timestamp for which this list was created, allowing the next
		// invocation to start from the point where this invocation left off.
		return []string{"er_0123456789"}, time.Now(), nil
	}
	resp, err := pagination.ListRefresh(context.Background(), refreshToken, grantsHash, pageSize, filterItemFunc, listItemsFunc, estimatedCountFunc, deletedIdsFunc)
	if err != nil {
		fmt.Println("failed to paginate", err)
		return
	}
	fmt.Println("Got results:")
	for _, item := range resp.Items {
		fmt.Printf("\tValue: %d\n", item.Value)
	}
	if resp.CompleteListing {
		fmt.Println("Listing was complete")
	} else {
		fmt.Println("Listing was not complete")
	}
	fmt.Println("There are an estimated", resp.EstimatedItemCount, "total items available")
	fmt.Println("The following resources have been deleted since we last saw them:")
	for _, id := range resp.DeletedIds {
		fmt.Println("\t" + id)
	}
	// Output: Got results:
	//	Value: 0
	//	Value: 1
	//	Value: 2
	//	Value: 3
	//	Value: 4
	//	Value: 0
	//	Value: 1
	//	Value: 2
	//	Value: 3
	//	Value: 4
	// Listing was not complete
	// There are an estimated 1000 total items available
	// The following resources have been deleted since we last saw them:
	//	er_0123456789
}
