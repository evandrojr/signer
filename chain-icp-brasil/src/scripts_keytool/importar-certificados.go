package main

import (
	"bufio"
	"fmt"
	"io"
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
	// Exibe log na tela e salva em arquivo
	log.SetOutput(io.MultiWriter(os.Stdout, logFile))

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

	failedImport := make(map[string]string)
	validCertificates := make(map[string]string)
	// Insere e valida certificados
	insertNewKeys("./novascadeias", keystore, password, providerPath, failedImport, validCertificates)

	// Validação final
	fmt.Println("Starting final validation...")
	_, actualAliases, failedValidation := validateKeystore(keystore, password, validCertificates, providerPath)

	// Resumo
	fmt.Printf("\n--- Resumo da Importação ---\n")
	fmt.Printf("Certificados válidos importados: %d\n", len(actualAliases))
	fmt.Printf("Certificados com erro de importação: %d\n", len(failedImport))
	fmt.Printf("Certificados com erro de validação: %d\n", len(failedValidation))

	if len(failedImport) > 0 {
		fmt.Printf("\n--- Erros de Importação ---\n")
		for cert, reason := range failedImport {
			fmt.Printf("Certificado: %s\nMotivo: %s\n", cert, reason)
		}
	}
	if len(failedValidation) > 0 {
		fmt.Printf("\n--- Erros de Validação ---\n")
		for cert, reason := range failedValidation {
			fmt.Printf("Certificado: %s\nMotivo: %s\n", cert, reason)
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

func insertNewKeys(certsDir, keystore, password, providerPath string, failedImport, validCertificates map[string]string) {
	files, err := ioutil.ReadDir(certsDir)
	if err != nil {
		log.Printf("ERROR: Could not read directory %s: %v", certsDir, err)
		return
	}

	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".crt") {
			alias := strings.TrimSuffix(file.Name(), filepath.Ext(file.Name()))
			certPath := filepath.Join(certsDir, file.Name())

			fmt.Printf("\nProcessando certificado: %s\n", file.Name())

			// Valida certificado
			cmd := exec.Command("openssl", "x509", "-in", certPath, "-noout")
			if err := cmd.Run(); err != nil {
				msg := "Não é um certificado X.509 válido"
				failedImport[file.Name()] = msg
				fmt.Printf("Falha ao validar %s: %s\n", file.Name(), msg)
				continue
			}

			// Importa certificado
			cmd = exec.Command("keytool", "-importcert", "-keystore", keystore, "-storepass", password, "-file", certPath, "-alias", alias, "-storetype", "BKS", "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", providerPath, "-noprompt")
			output, err := cmd.CombinedOutput()
			if err != nil {
				failedImport[file.Name()] = string(output)
				fmt.Printf("Falha ao importar %s: %s\n", file.Name(), string(output))
			} else {
				validCertificates[alias] = file.Name()
				fmt.Printf("Certificado importado com sucesso: %s\n", file.Name())
			}
		}
	}
}

func validateKeystore(keystore, password string, validCertificates map[string]string, providerPath string) (bool, map[string]bool, map[string]string) {
	log.Println("Starting keystore validation...")

	// Lista aliases do keystore
	cmd := exec.Command("keytool", "-list", "-keystore", keystore, "-storepass", password, "-storetype", "BKS", "-provider", "org.bouncycastle.jce.provider.BouncyCastleProvider", "-providerpath", providerPath)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("VALIDATION ERROR: Failed to list keys from keystore '%s': %s", keystore, string(out))
		return false, nil, nil
	}

	actualAliases := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(string(out)))
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

	// Verifica certificados ausentes
	failedValidation := make(map[string]string)
	for alias, certName := range validCertificates {
		if !actualAliases[alias] {
			failedValidation[certName] = "Não está presente no keystore após importação"
		}
	}

	success := len(failedValidation) == 0
	return success, actualAliases, failedValidation
}