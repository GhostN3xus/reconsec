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
		return Model{Bias: -1.0, Weights: map[string]float64{
			"param_name_entropy": 0.8,
			"is_in_path":         0.5,
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
	return 1.0 / (1.0 + math.Exp(-s))
}
