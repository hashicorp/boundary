// +build genapi

package main

func main() {
	parsePBs()
	writeStructTemplates()
	writeCreateFuncs()
}
