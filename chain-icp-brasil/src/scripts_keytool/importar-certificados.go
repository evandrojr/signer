package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func main() {
	logFile, err := os.OpenFile("import.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Println("Starting certificate import process...")

	config, err := readConfig("config_bks.ini")
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	keystore := config["cacerts"]
	password := config["password"]

	if err := os.Remove(keystore); err == nil {
		log.Printf("Removed old keystore '%s'.\n", keystore)
    }

    wd, err := os.Getwd()
    if err != nil {
        log.Fatalf("Failed to get current working directory: %v", err)
    }
    providerPath := filepath.Join(wd, "bcprov-jdk15on-1.65.jar")

	failedCertificates := make(map[string]string)
    // Insert all keys from the directory
    insertNewKeys("./novascadeias", keystore, password, providerPath, failedCertificates)

	// Final Validation
	fmt.Println("Starting final validation...")
	success, _, actualAliases := validateKeystore(keystore, password, "./novascadeias", providerPath)
	if success {
		log.Println("SUCCESS: All certificates were imported successfully.")
		fmt.Println("SUCCESS: All certificates were imported successfully. See import.log for details.")
	} else {
		log.Println("VALIDATION FAILED: Not all certificates were imported.")
		fmt.Println("VALIDATION FAILED: Not all certificates were imported. Check import.log for details.")
	}

	successCount := len(actualAliases)
	failureCount := len(failedCertificates)

	fmt.Printf("\n--- Import Summary ---\nSuccessfully imported certificates: %d\nFailed to import certificates: %d\n", successCount, failureCount)
	
	if failureCount > 0 {
		fmt.Printf("\n--- Details of Failed Certificates ---\n")
		for cert, reason := range failedCertificates {
			fmt.Printf("Certificate: %s\nReason: %s\n", cert, reason)
		}
	}
}

func readConfig(filename string) (map[string]string, error) {
	config := make(map[string]string)
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			config[parts[0]] = parts[1]
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return config, nil
}

func insertNewKeys(certsDir, keystore, password, providerPath string, failedCertificates map[string]string) {
	files, err := ioutil.ReadDir(certsDir)
	if err != nil {
		log.Printf("ERROR: Could not read directory %s: %v", certsDir, err)
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".crt") {
			fmt.Printf("Processing certificate %s...\n", file.Name())
			alias := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			certPath := filepath.Join(certsDir, file.Name())

			// Validate the certificate before importing
			cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout")
			if err := cmd.Run(); err != nil {
				log.Printf("SKIPPING: '%s' is not a valid X.509 certificate.\n", file.Name())
				failedCertificates[file.Name()] = "Not a valid X.509 certificate"
				continue
			}

			cmd = exec.Command("keytool", "-importcert", "-keystore", keystore, "-storepass", password, "-file", certPath, "-alias", alias, "-storetype", "BKS", "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", providerPath, "-noprompt")
			fmt.Println("Executing command:", cmd.String())
			output, err := cmd.CombinedOutput()
			if err != nil {
				log.Printf("ERROR: Failed to import key for '%s'. Reason: %s\n", alias, string(output))
				failedCertificates[file.Name()] = string(output)
			} else {
				log.Printf("SUCCESS: Imported key for '%s' from '%s'\n", alias, certPath)
			}
		}
	}
}

func validateKeystore(keystore, password, certsDir, providerPath string) (bool, int, map[string]bool) {
	log.Println("Starting keystore validation...")

	// Get expected aliases from the import log
	expectedAliases := make(map[string]bool)
	logFile, err := os.Open("import.log")
	if err != nil {
		log.Printf("VALIDATION ERROR: Could not read log file: %v", err)
		return false, 0, nil
	}
	defer logFile.Close()

	scanner := bufio.NewScanner(logFile)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "SUCCESS: Imported key for") {
			parts := strings.Split(line, "'")
			if len(parts) > 1 {
				alias := parts[1]
				expectedAliases[alias] = true
			}
		}
	}

	// Get actual aliases from the keystore
	cmd := exec.Command("keytool", "-list", "-keystore", keystore, "-storepass", password, "-storetype", "BKS", "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", providerPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("VALIDATION ERROR: Failed to list keys from keystore '%s': %s", keystore, string(out))
		return false, 0, nil
	}

	actualAliases := make(map[string]bool)
	scanner = bufio.NewScanner(strings.NewReader(string(out)))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "trustedCertEntry") {
			parts := strings.SplitN(line, ",", 2)
			if len(parts) > 0 {
				alias := strings.TrimSpace(parts[0])
				actualAliases[alias] = true
			}
		}
	}

	// Compare the two lists
	missingCount := 0
	for alias := range expectedAliases {
		if !actualAliases[alias] {
			log.Printf("VALIDATION FAILED: Certificate with alias '%s' is missing from the keystore.\n", alias)
			missingCount++
		}
	}

	if missingCount > 0 {
		log.Printf("VALIDATION FAILED: %d certificates are missing.\n", missingCount)
		return false, len(expectedAliases), actualAliases
	}

	log.Println("VALIDATION SUCCESS: All expected certificates are present in the keystore.")
	return true, len(expectedAliases), actualAliases
}