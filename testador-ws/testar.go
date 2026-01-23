package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"testador-ws-assinador-serpro/config"
	"testador-ws-assinador-serpro/requests"

	"golang.org/x/net/websocket"
)

// Constantes movidas para config.go

type TestMessage struct {
	ID             string          `json:"id"`
	FileName       string          `json:"fileName"`
	MessageContent json.RawMessage `json:"messageContent"`
	ExpectedToFail bool            `json:"expectedToFail,omitempty"`
	Description    string          `json:"description,omitempty"`
}

func main() {
	update := flag.Bool("update", false, "Update golden files")
	testGolden := flag.Bool("test-golden", false, "Test against golden files")
	testFile := flag.String("t", config.TestMessagesFile, "File with test messages")
	flag.Parse()

	os.Mkdir(config.SignedFilesDir, 0755)

	if *update {
		fmt.Println("Update mode enabled: Golden files will be updated.")
		os.Mkdir(config.GoldenFilesDir, 0755)
	}

	syntheticLogFile, err := os.Create("synthetic.log")
	if err != nil {
		log.Fatalf("Failed to create synthetic log file: %v", err)
	}
	defer syntheticLogFile.Close()

	detailedLogFile, err := os.Create("detailed.log")
	if err != nil {
		log.Fatalf("Failed to create detailed log file: %v", err)
	}
	defer detailedLogFile.Close()

	// Criar um MultiWriter para escrever tanto no arquivo quanto na tela para o log sintético
	syntheticMultiWriter := io.MultiWriter(syntheticLogFile, os.Stdout)
	syntheticLogger := log.New(syntheticMultiWriter, "", log.Ldate|log.Ltime)
	detailedLogger := log.New(detailedLogFile, "", log.Ldate|log.Ltime)

	ws, err := websocket.Dial(config.ServerURL, "", "http://localhost/")
	if err != nil {
		log.Fatal(err)
	}
	defer ws.Close()

	// Read test messages from JSON file
	data, err := os.ReadFile(*testFile)
	if err != nil {
		log.Fatalf("Error reading test messages file: %v", err)
	}

	var testMessages []TestMessage
	if err := json.Unmarshal(data, &testMessages); err != nil {
		log.Fatalf("Error unmarshalling test messages: %v", err)
	}

	fmt.Printf("Iniciando testes de %d mensagens. Resultados:\n", len(testMessages))
	fmt.Println("====================================================")

	var totalTests, testsPassed, testsFailed int
	for _, msg := range testMessages {
		totalTests++
		if requests.ProcessAndSend(ws, msg.MessageContent, syntheticLogger, detailedLogger, msg.ID, *update, *testGolden, msg.ExpectedToFail, msg.Description) {
			testsPassed++
		} else {
			testsFailed++
		}
	}

	fmt.Println("====================================================")
	fmt.Printf("Total de testes: %d\n", totalTests)
	fmt.Printf("Testes passados: %d\n", testsPassed)
	fmt.Printf("Testes com falha: %d\n", testsFailed)
	fmt.Println("====================================================")
	fmt.Println("Testes concluídos. Logs detalhados salvos em 'detailed.log' e sintéticos em 'synthetic.log'.")
}
