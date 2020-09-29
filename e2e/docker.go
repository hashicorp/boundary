// +build integration

package e2e

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"
)

const dockerContainerName = "test"

var dockerTag = "boundary"

func build() error {
	p, err := rootPath()
	if err != nil {
		return err
	}

	rev, err := rev()
	if err != nil {
		return err
	}

	dockerTag = dockerTag + ":" + rev

	cmdStr := fmt.Sprintf("docker build -t %s -f %s/Dockerfile %s/", dockerTag, p, p)
	fmt.Printf("building boundary ... %s", cmdStr)
	cmd := exec.Command("/bin/sh", "-c", cmdStr)

	pipe, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		return err
	}

	reader := bufio.NewReader(pipe)
	line, err := reader.ReadString('\n')
	for err == nil {
		fmt.Println(line)
		line, err = reader.ReadString('\n')
	}
	cmd.Wait()

	return nil
}

func copyToHost() error {
	p, err := rootPath()
	if err != nil {
		return err
	}

	cmd := []string{"cp", "test:/go/bin/boundary", fmt.Sprintf("%s/bin/boundary", p)}

	fmt.Printf("copying binary from docker to host: %v\n", cmd)

	r, err := exec.Command("docker", cmd...).CombinedOutput()
	if len(r) != 0 {
		fmt.Printf("result: %s\n", r)
	}

	return err
}

func createContainer() error {
	cmd := []string{"create", "-it", "--name", dockerContainerName, dockerTag}

	fmt.Printf("creating container for copy operation: %v\n", cmd)

	r, err := exec.Command("docker", cmd...).CombinedOutput()
	if len(r) != 0 {
		fmt.Printf("result: %s\n", r)
	}

	return err
}

func removeContainer() error {
	cmd := []string{"container", "rm", dockerContainerName}

	fmt.Printf("removing container: %v\n", cmd)

	r, err := exec.Command("docker", cmd...).CombinedOutput()
	if len(r) != 0 {
		fmt.Printf("result: %s\n", r)
	}

	return err
}

func rev() (string, error) {
	r, err := exec.Command("git", "rev-parse", "HEAD").Output()
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(r)), nil
}

func rootPath() (string, error) {
	path, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(path)), nil
}
