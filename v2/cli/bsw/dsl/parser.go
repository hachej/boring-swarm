package dsl

import (
	"bytes"
	"fmt"
	"io"
	"os"
)

import "gopkg.in/yaml.v3"

func ParseFile(path string) (*FlowSpec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read flow: %w", err)
	}
	return ParseBytes(data)
}

func ParseBytes(data []byte) (*FlowSpec, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)

	var spec FlowSpec
	if err := dec.Decode(&spec); err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("empty flow spec")
		}
		return nil, fmt.Errorf("parse flow: %w", err)
	}
	if err := Validate(spec); err != nil {
		return nil, err
	}
	return &spec, nil
}
