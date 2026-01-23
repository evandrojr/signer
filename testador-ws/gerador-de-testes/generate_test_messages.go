

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"strconv"
	"strings"
)

type Message struct {
	ID             string                 `json:"id"`
	FileName       string                 `json:"fileName"`
	MessageContent map[string]interface{} `json:"messageContent"`
}

func main() {
	testsDir := "tests"
	files, err := ioutil.ReadDir(testsDir)
	if err != nil {
		fmt.Println("Error reading tests directory:", err)
		return
	}

	var messages []Message
	id := 1

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".txt") {
			filePath := filepath.Join(testsDir, file.Name())
			content, err := ioutil.ReadFile(filePath)
			if err != nil {
				fmt.Printf("Error reading file %s: %v\n", filePath, err)
				continue
			}

			lines := strings.Split(string(content), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "{") && strings.HasSuffix(line, "}") {
					var messageContent map[string]interface{}
					err := json.Unmarshal([]byte(line), &messageContent)
					if err == nil {
						messages = append(messages, Message{
							ID:             strconv.Itoa(id),
							FileName:       file.Name(),
							MessageContent: messageContent,
						})
						id++
					}
				}
			}
		}
	}

	jsonOutput, err := json.MarshalIndent(messages, "", "  ")
	if err != nil {
		fmt.Println("Error marshalling to JSON:", err)
		return
	}

	err = ioutil.WriteFile("test_messages.json", jsonOutput, 0644)
	if err != nil {
		fmt.Println("Error writing to test_messages.json:", err)
		return
	}

	fmt.Println("test_messages.json generated successfully.")
}
