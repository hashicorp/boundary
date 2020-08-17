package static_test

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/host/static"
)

func ExampleNewHostCatalog() {
	projectPublicId := "p_1234"
	catalog, _ := static.NewHostCatalog(projectPublicId, static.WithName("my catalog"))
	fmt.Println(catalog.Name)
	// Output:
	// my catalog
}

func ExampleNewHost() {
	catalogPublicId := "sthc_1234"
	host, _ := static.NewHost(catalogPublicId, "127.0.0.1")
	fmt.Println(host.Address)
	// Output:
	// 127.0.0.1
}

func ExampleNewHostSet() {
	catalogPublicId := "sthc_1234"
	set, _ := static.NewHostSet(catalogPublicId, static.WithName("my host set"))
	fmt.Println(set.Name)
	// Output:
	// my host set
}

func ExampleNewHostSetMember() {
	setPublicId := "sths_11111"
	hostPublicId := "sth_22222"
	member, _ := static.NewHostSetMember(setPublicId, hostPublicId)
	fmt.Println(member.SetId)
	fmt.Println(member.HostId)
}
