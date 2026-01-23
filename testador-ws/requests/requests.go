package requests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"testador-ws-assinador-serpro/config"

	"golang.org/x/net/websocket"
)

// Constantes movidas para o pacote config

type Request struct {
	Command               string   `json:"command,omitempty"`
	Type                  string   `json:"type,omitempty"`
	InputData             string   `json:"inputData,omitempty"`
	ListOfInputData       []string `json:"listOfInputData,omitempty"`
	InputSignature        string   `json:"inputSignature,omitempty"`
	ListOfInputSignatures []string `json:"listOfInputSignatures,omitempty"`
	AlgorithmOIDHash      string   `json:"algorithmOIDHash,omitempty"`
	TextEncoding          string   `json:"textEncoding,omitempty"`
	Attached              string   `json:"attached,omitempty"`
	SignaturePolicy       string   `json:"signaturePolicy,omitempty"`
	Algorithm             string   `json:"algorithm,omitempty"`
	OutputDataType        string   `json:"outputDataType,omitempty"`
	ReferenceID           string   `json:"referenceId,omitempty"`
	SignatureToCoSign     string   `json:"signatureToCoSign,omitempty"`
}

func getSignedFileExtension(command string) string {
	switch command {
	case "signxml", "signxmldsig":
		return ".xml"
	default:
		return ".p7s"
	}
}

func ProcessAndSend(ws *websocket.Conn, content json.RawMessage, syntheticLogger, detailedLogger *log.Logger, messageID string, update, testGolden, expectedToFail bool, description string) bool {
	var req Request
	if err := json.Unmarshal(content, &req); err != nil {
		detailedLogger.Printf("Error unmarshalling JSON for message ID %s: %v", messageID, err)
		return false
	}

	if expectedToFail {
		detailedLogger.Printf("Sending request for message ID %s (Expected to FAIL - %s): %+v", messageID, description, req)
	} else {
		detailedLogger.Printf("Sending request for message ID %s: %+v", messageID, req)
	}

	if err := ws.SetWriteDeadline(time.Now().Add(config.TestTimeout * time.Second)); err != nil {
		detailedLogger.Printf("Error setting write deadline for message ID %s: %v", messageID, err)
		return false
	}

	if err := websocket.JSON.Send(ws, req); err != nil {
		detailedLogger.Printf("Error sending request for message ID %s: %v", messageID, err)
		return false
	}

	if err := ws.SetReadDeadline(time.Now().Add(config.TestTimeout * time.Second)); err != nil {
		detailedLogger.Printf("Error receiving response for message ID %s: %v", messageID, err)
		syntheticLogger.Printf("ID: %s, Status: Failure, Command: %s", messageID, req.Command)
		return false
	}

	var response map[string]interface{}
	decoder := json.NewDecoder(ws)
	decoder.UseNumber()
	if err := decoder.Decode(&response); err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			syntheticLogger.Printf("ID: %s, Status: Timeout, Command: %s", messageID, req.Command)
		} else {
			syntheticLogger.Printf("ID: %s, Status: Failure, Command: %s", messageID, req.Command)
		}
		detailedLogger.Printf("Error receiving response for message ID %s: %v", messageID, err)
		return false
	}

	if cancelled, ok := response["actionCanceled"].(bool); ok && cancelled {
		syntheticLogger.Printf("ID: %s, Status: Cancelled, Command: %s", messageID, req.Command)
		return false
	}

	delete(response, "notAfterDateCertificate")
	delete(response, "SignatureValue")

	detailedLogger.Printf("Received response for message ID %s: %+v", messageID, response)

	if signatures, ok := response["listOfSignatures"].([]interface{}); ok {
		for i, sig := range signatures {
			if signature, ok := sig.(string); ok {
				signedFileName := fmt.Sprintf("%s-%d%s", messageID, i, getSignedFileExtension(req.Command))
				signedFilePath := filepath.Join(config.SignedFilesDir, signedFileName)
				if err := os.WriteFile(signedFilePath, []byte(signature), 0644); err != nil {
					detailedLogger.Printf("Error writing signed file for message ID %s: %v", messageID, err)
				}
			}
		}
	}

	goldenFileName := fmt.Sprintf("%s.golden", messageID)
	goldenFilePath := filepath.Join(config.GoldenFilesDir, goldenFileName)

	if update {
		file, err := os.Create(goldenFilePath)
		if err != nil {
			log.Printf("Error creating golden file %s: %v", goldenFilePath, err)
			return false
		}
		defer file.Close()

		encoder := json.NewEncoder(file)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			log.Printf("Error writing to golden file %s: %v", goldenFilePath, err)
		}

		syntheticLogger.Printf("ID: %s, Golden file updated: %s", messageID, goldenFileName)
		return true
	} else if testGolden {
		goldenData, err := os.ReadFile(goldenFilePath)
		if err != nil {
			syntheticLogger.Printf("ID: %s, Golden file not found: %s", messageID, goldenFileName)
			return false
		}

		delete(response, "notAfterDateCertificate")
		delete(response, "SignatureValue")

		var buffer bytes.Buffer
		encoder := json.NewEncoder(&buffer)
		encoder.SetEscapeHTML(false)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(response); err != nil {
			log.Printf("Error encoding response for comparison: %v", err)
			return false
		}

		if buffer.String() == string(goldenData) {
			syntheticLogger.Printf("ID: %s, Status: Success, Command: %s", messageID, req.Command)
			return true
		} else {
			syntheticLogger.Printf("ID: %s, Status: Failure, Command: %s", messageID, req.Command)
			return false
		}
	} else {
		hasError := false
		if _, ok := response["error"]; ok {
			hasError = true
		}
		
		// Se o teste é esperado falhar
		if expectedToFail {
			if hasError {
				// Teste passou: falhou como esperado
				if description != "" {
					syntheticLogger.Printf("ID: %s, Status: Success (Expected Failure: %s), Command: %s", messageID, description, req.Command)
				} else {
					syntheticLogger.Printf("ID: %s, Status: Success (Expected Failure), Command: %s", messageID, req.Command)
				}
				return true
			} else {
				// Teste falhou: deveria ter falhado mas passou
				if description != "" {
					syntheticLogger.Printf("ID: %s, Status: Failure (Should have failed: %s), Command: %s", messageID, description, req.Command)
				} else {
					syntheticLogger.Printf("ID: %s, Status: Failure (Should have failed), Command: %s", messageID, req.Command)
				}
				return false
			}
		} else {
			// Teste normal
			if hasError {
				syntheticLogger.Printf("ID: %s, Status: Failure, Command: %s", messageID, req.Command)
				return false
			} else {
				syntheticLogger.Printf("ID: %s, Status: Success, Command: %s", messageID, req.Command)
				return true
			}
		}
	}
}
