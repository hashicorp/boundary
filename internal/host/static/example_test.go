// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package static_test

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/host/static"
)

func ExampleNewHostCatalog() {
	projectPublicId := "p_1234"
	catalog, _ := static.NewHostCatalog(context.Background(), projectPublicId, static.WithName("my catalog"))
	fmt.Println(catalog.Name)
	// Output:
	// my catalog
}

func ExampleNewHost() {
	catalogPublicId := "hcst_1234"
	host, _ := static.NewHost(context.Background(), catalogPublicId, static.WithAddress("127.0.0.1"))
	fmt.Println(host.Address)
	// Output:
	// 127.0.0.1
}

func ExampleNewHostSet() {
	catalogPublicId := "hcst_1234"
	set, _ := static.NewHostSet(context.Background(), catalogPublicId, static.WithName("my host set"))
	fmt.Println(set.Name)
	// Output:
	// my host set
}

func ExampleNewHostSetMember() {
	setPublicId := "hsst_11111"
	hostPublicId := "hst_22222"
	member, _ := static.NewHostSetMember(context.Background(), setPublicId, hostPublicId)
	fmt.Println(member.SetId)
	fmt.Println(member.HostId)
}
