package static_test

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/host"
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
	catalogPublicId := "hcst_1234"
	host, _ := static.NewHost(catalogPublicId, static.WithAddress("127.0.0.1"))
	fmt.Println(host.Address)
	// Output:
	// 127.0.0.1
}

func ExampleNewHostSet() {
	catalogPublicId := "hcst_1234"
	set, _ := static.NewHostSet(catalogPublicId, static.WithName("my host set"))
	fmt.Println(set.Name)
	// Output:
	// my host set
}

func ExampleNewHostSetMember() {
	setPublicId := "hsst_11111"
	hostPublicId := "hst_22222"
	member, _ := host.NewSetMember(setPublicId, hostPublicId)
	fmt.Println(member.SetId)
	fmt.Println(member.HostId)
}
