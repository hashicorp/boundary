package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/template"
)

// generate looks for migration sql in a directory for the given dialect and
// applies the templates below to the contents of the files, building up a
// migrations map for the dialect
func generate(dialect string) {
	baseDir := os.Getenv("GEN_BASEPATH") + "/internal/db/schema"
	srcDir := baseDir + "/migrations"
	dir, err := os.Open(fmt.Sprintf("%s/%s", srcDir, dialect))
	if err != nil {
		fmt.Printf("error opening dir with dialect %s: %v\n", dialect, err)
		os.Exit(1)
	}
	versions, err := dir.Readdirnames(0)
	if err != nil {
		fmt.Printf("error reading dir names with dialect %s: %v\n", dialect, err)
		os.Exit(1)
	}
	sort.Strings(versions)

	type ContentValues struct {
		Name    string
		Content string
	}
	var upContents []ContentValues

	isDev := false
	var lRelVer, largestSchemaVersion int
	for _, ver := range versions {
		var verVal int
		switch ver {
		case "dev":
			verVal = lRelVer + 1
		default:
			v, err := strconv.Atoi(ver)
			if err != nil {
				fmt.Printf("error reading major schema version directory %q.  Must be a number or 'dev'\n", ver)
				os.Exit(1)
			}
			verVal = v
			if verVal > lRelVer {
				lRelVer = verVal
			}
		}

		dir, err := os.Open(fmt.Sprintf("%s/%s/%s", srcDir, dialect, ver))
		if err != nil {
			fmt.Printf("error opening dir with dialect %s: %v\n", dialect, err)
			os.Exit(1)
		}
		names, err := dir.Readdirnames(0)
		if err != nil {
			fmt.Printf("error reading dir names with dialect %s: %v\n", dialect, err)
			os.Exit(1)
		}

		if ver == "dev" && len(names) > 0 {
			isDev = true
		}

		sort.Strings(names)
		for _, name := range names {
			if !strings.HasSuffix(name, ".sql") {
				continue
			}

			contents, err := ioutil.ReadFile(fmt.Sprintf("%s/%s/%s/%s", srcDir, dialect, ver, name))
			if err != nil {
				fmt.Printf("error opening file %s with dialect %s: %v", name, dialect, err)
				os.Exit(1)
			}

			nameParts := strings.SplitN(name, "_", 2)
			if len(nameParts) != 2 {
				continue
			}

			v, err := strconv.Atoi(nameParts[0])
			if err != nil {
				fmt.Printf("Unable to get file version from %q\n", name)
				continue
			}

			fullV := (verVal * 1000) + v
			if fullV > largestSchemaVersion {
				largestSchemaVersion = fullV
			}
			cv := ContentValues{
				Name:    fmt.Sprint(fullV),
				Content: string(contents),
			}
			switch {
			case strings.Contains(nameParts[1], ".up."):
				upContents = append(upContents, cv)
			}
		}
	}

	outBuf := bytes.NewBuffer(nil)
	if err := migrationsTemplate.Execute(outBuf, struct {
		Type                string
		UpValues            []ContentValues
		DevMigration        bool
		BinarySchemaVersion int
	}{
		Type:                dialect,
		UpValues:            upContents,
		DevMigration:        isDev,
		BinarySchemaVersion: largestSchemaVersion,
	}); err != nil {
		fmt.Printf("error executing migrations value template for dialect %s: %s", dialect, err)
		os.Exit(1)
	}

	outFile := fmt.Sprintf("%s/%s_migration.gen.go", baseDir, dialect)
	if err := ioutil.WriteFile(outFile, outBuf.Bytes(), 0o644); err != nil {
		fmt.Printf("error writing file %q: %v\n", outFile, err)
		os.Exit(1)
	}
}

var migrationsTemplate = template.Must(template.Must(template.New("Content").Parse(
	`{{ .Name }}: []byte(` + "`\n{{ .Content }}\n`" + `),
`)).New("MainPage").Parse(`package schema

// Code generated by "make migrations"; DO NOT EDIT.

func init() {
	migrationStates["{{ .Type }}"] = migrationState{
		devMigration: {{ .DevMigration }},
		binarySchemaVersion: {{ .BinarySchemaVersion }},
		upMigrations: map[int][]byte{
			{{range .UpValues }}{{ template "Content" . }}{{end}}
		},
	}
}
`))
