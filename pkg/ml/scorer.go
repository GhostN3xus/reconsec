package ml

import (
	"encoding/json"
	"math"
	"os"
)

type Model struct {
	Bias    float64            `json:"bias"`
	Weights map[string]float64 `json:"weights"`
}

func LoadModel(path string) (Model, error) {
	if path == "" {
		// Retorna um modelo padrão se nenhum caminho for fornecido
		return Model{Bias: -1.0, Weights: map[string]float64{
			"param_name_entropy": 0.8,
			"param_name_len":     0.2, // Adicionado um novo peso para o comprimento
			"is_common_name":     1.5, // Adicionado peso para nomes comuns
		}}, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return Model{}, err
	}
	defer f.Close()
	var m Model
	if err := json.NewDecoder(f).Decode(&m); err != nil {
		return Model{}, err
	}
	return m, nil
}

func (m Model) Score(features map[string]float64) float64 {
	s := m.Bias
	for k, v := range features {
		if w, ok := m.Weights[k]; ok {
			s += w * v
		}
	}
	// Função sigmoide para retornar uma pontuação entre 0 e 1
	return 1.0 / (1.0 + math.Exp(-s))
}

// CalculateEntropy calcula a entropia de Shannon de uma string.
func CalculateEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	counts := make(map[rune]int)
	for _, r := range s {
		counts[r]++
	}

	var entropy float64
	length := float64(len(s))
	for _, count := range counts {
		p := float64(count) / length
		entropy -= p * math.Log2(p)
	}
	return entropy
}
