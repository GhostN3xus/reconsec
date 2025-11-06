package discovery

import (
	"fmt"
	"os/exec"
)

// RunDirScan executa o dirsearch com configurações otimizadas para uma varredura profunda.
func RunDirScan(baseURL string) (string, error) {
	// 2. Executa o dirsearch com flags otimizadas
	fmt.Printf("Iniciando varredura profunda com dirsearch em %s...\n", baseURL)

	outputFile := "dirsearch_report.txt"
	cmd := exec.Command("dirsearch", "-u", baseURL, "-r", "-f", "-x", "400,403,404,500", "--plain-text-report", "--output="+outputFile)

	output, err := cmd.CombinedOutput()
	if err != nil {
		// A saída pode conter informações úteis mesmo em caso de erro
		return string(output), fmt.Errorf("erro ao executar o dirsearch: %w", err)
	}

	// 3. Lê e retorna o conteúdo do relatório
	reportContent, err := exec.Command("cat", outputFile).Output()
	if err != nil {
		return string(output), fmt.Errorf("falha ao ler o relatório do dirsearch: %w", err)
	}

	// Limpa o arquivo de relatório
	exec.Command("rm", outputFile).Run()

	return string(reportContent), nil
}
