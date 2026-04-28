// Command specvalidate validates JSON documents against VIBAP mission governance
// JSON Schemas. It parses schemas to extract constraints (required fields, types,
// enums, patterns, min/max) and checks documents structurally. No external JSON
// Schema libraries are used.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type Schema struct {
	Type                 string             `json:"type"`
	Required             []string           `json:"required"`
	Properties           map[string]*Schema `json:"properties"`
	AdditionalProperties *json.RawMessage   `json:"additionalProperties"`
	Items                *Schema            `json:"items"`
	Enum                 []interface{}      `json:"enum"`
	MinLength            *int               `json:"minLength"`
	MinItems             *int               `json:"minItems"`
	Minimum              *float64           `json:"minimum"`
	Maximum              *float64           `json:"maximum"`
	Pattern              string             `json:"pattern"`
	Format               string             `json:"format"`
	Ref                  string             `json:"$ref"`
	Defs                 map[string]*Schema `json:"$defs"`
}

type ValidationError struct {
	Path    string
	Message string
}

func (e ValidationError) String() string {
	if e.Path == "" {
		return e.Message
	}
	return fmt.Sprintf("%s: %s", e.Path, e.Message)
}

type Validator struct {
	root      *Schema
	refCache  map[string]*Schema
	schemaDir string
}

func NewValidator(schema *Schema, schemaDir string) *Validator {
	v := &Validator{
		root:      schema,
		refCache:  make(map[string]*Schema),
		schemaDir: schemaDir,
	}
	return v
}

func (v *Validator) Validate(doc interface{}) []ValidationError {
	return v.validate(v.root, doc, "")
}

func readUserJSONFile(path string) ([]byte, error) {
	cleaned := filepath.Clean(path)
	// #nosec G304 -- this CLI intentionally validates user-specified local files.
	data, err := os.ReadFile(cleaned)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func readSchemaRefFile(schemaDir, ref string) ([]byte, error) {
	base := filepath.Clean(schemaDir)
	path := filepath.Clean(filepath.Join(base, ref))
	rel, err := filepath.Rel(base, path)
	if err != nil {
		return nil, fmt.Errorf("resolve $ref path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return nil, fmt.Errorf("$ref %s escapes schema directory", ref)
	}
	// #nosec G304 -- the path is normalized and constrained to schemaDir above.
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func (v *Validator) resolveRef(ref string) (*Schema, error) {
	if cached, ok := v.refCache[ref]; ok {
		return cached, nil
	}

	if strings.HasPrefix(ref, "#/$defs/") {
		name := strings.TrimPrefix(ref, "#/$defs/")
		if v.root.Defs != nil {
			if s, ok := v.root.Defs[name]; ok {
				v.refCache[ref] = s
				return s, nil
			}
		}
		return nil, fmt.Errorf("unresolved local $ref: %s", ref)
	}

	data, err := readSchemaRefFile(v.schemaDir, ref)
	if err != nil {
		return nil, fmt.Errorf("cannot read $ref file %s: %w", ref, err)
	}
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("cannot parse $ref file %s: %w", ref, err)
	}
	v.refCache[ref] = &s
	return &s, nil
}

func (v *Validator) validate(schema *Schema, value interface{}, path string) []ValidationError {
	if schema == nil {
		return nil
	}

	if schema.Ref != "" {
		resolved, err := v.resolveRef(schema.Ref)
		if err != nil {
			return []ValidationError{{Path: path, Message: err.Error()}}
		}
		return v.validate(resolved, value, path)
	}

	var errs []ValidationError

	if schema.Type != "" {
		errs = append(errs, v.checkType(schema, value, path)...)
	}

	if schema.Enum != nil {
		errs = append(errs, v.checkEnum(schema, value, path)...)
	}

	if schema.Type == "object" || (schema.Type == "" && schema.Properties != nil) {
		errs = append(errs, v.checkObject(schema, value, path)...)
	}

	if schema.Type == "array" {
		errs = append(errs, v.checkArray(schema, value, path)...)
	}

	if schema.Type == "string" || schema.Type == "" {
		if s, ok := value.(string); ok {
			errs = append(errs, v.checkString(schema, s, path)...)
		}
	}

	if schema.Type == "number" || schema.Type == "integer" {
		errs = append(errs, v.checkNumber(schema, value, path)...)
	}

	return errs
}

func (v *Validator) checkType(schema *Schema, value interface{}, path string) []ValidationError {
	if value == nil {
		return []ValidationError{{Path: path, Message: fmt.Sprintf("expected type %s, got null", schema.Type)}}
	}

	switch schema.Type {
	case "object":
		if _, ok := value.(map[string]interface{}); !ok {
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected object, got %T", value)}}
		}
	case "array":
		if _, ok := value.([]interface{}); !ok {
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected array, got %T", value)}}
		}
	case "string":
		if _, ok := value.(string); !ok {
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected string, got %T", value)}}
		}
	case "integer":
		switch n := value.(type) {
		case float64:
			if n != math.Trunc(n) {
				return []ValidationError{{Path: path, Message: fmt.Sprintf("expected integer, got float %v", n)}}
			}
		default:
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected integer, got %T", value)}}
		}
	case "number":
		if _, ok := value.(float64); !ok {
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected number, got %T", value)}}
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return []ValidationError{{Path: path, Message: fmt.Sprintf("expected boolean, got %T", value)}}
		}
	}
	return nil
}

func (v *Validator) checkEnum(schema *Schema, value interface{}, path string) []ValidationError {
	for _, allowed := range schema.Enum {
		if fmt.Sprintf("%v", allowed) == fmt.Sprintf("%v", value) {
			return nil
		}
	}
	strs := make([]string, len(schema.Enum))
	for i, e := range schema.Enum {
		strs[i] = fmt.Sprintf("%v", e)
	}
	return []ValidationError{{Path: path, Message: fmt.Sprintf("value %q not in enum [%s]", fmt.Sprintf("%v", value), strings.Join(strs, ", "))}}
}

func (v *Validator) checkObject(schema *Schema, value interface{}, path string) []ValidationError {
	obj, ok := value.(map[string]interface{})
	if !ok {
		return nil
	}

	var errs []ValidationError

	for _, req := range schema.Required {
		if _, exists := obj[req]; !exists {
			errs = append(errs, ValidationError{
				Path:    joinPath(path, req),
				Message: "required field missing",
			})
		}
	}

	for key, val := range obj {
		propSchema, hasProp := schema.Properties[key]
		if hasProp {
			errs = append(errs, v.validate(propSchema, val, joinPath(path, key))...)
		} else if schema.AdditionalProperties != nil {
			switch strings.TrimSpace(string(*schema.AdditionalProperties)) {
			case "false":
				errs = append(errs, ValidationError{
					Path:    joinPath(path, key),
					Message: "field is not allowed by the schema",
				})
				continue
			case "true":
				continue
			}
			var apSchema Schema
			if err := json.Unmarshal(*schema.AdditionalProperties, &apSchema); err == nil && apSchema.Type != "" {
				errs = append(errs, v.validate(&apSchema, val, joinPath(path, key))...)
			}
		}
	}

	return errs
}

func (v *Validator) checkArray(schema *Schema, value interface{}, path string) []ValidationError {
	arr, ok := value.([]interface{})
	if !ok {
		return nil
	}

	var errs []ValidationError

	if schema.MinItems != nil && len(arr) < *schema.MinItems {
		errs = append(errs, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("array has %d items, minimum is %d", len(arr), *schema.MinItems),
		})
	}

	if schema.Items != nil {
		for i, item := range arr {
			errs = append(errs, v.validate(schema.Items, item, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}

	return errs
}

func (v *Validator) checkString(schema *Schema, s string, path string) []ValidationError {
	var errs []ValidationError

	if schema.MinLength != nil && len(s) < *schema.MinLength {
		errs = append(errs, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("string length %d is less than minimum %d", len(s), *schema.MinLength),
		})
	}

	if schema.Pattern != "" {
		matched, err := regexp.MatchString(schema.Pattern, s)
		if err != nil {
			errs = append(errs, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("invalid schema pattern %s: %v", schema.Pattern, err),
			})
		} else if !matched {
			errs = append(errs, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string %q does not match pattern %s", s, schema.Pattern),
			})
		}
	}

	if schema.Format == "date-time" {
		if !isValidDateTime(s) {
			errs = append(errs, ValidationError{
				Path:    path,
				Message: fmt.Sprintf("string %q is not a valid date-time", s),
			})
		}
	}

	return errs
}

func (v *Validator) checkNumber(schema *Schema, value interface{}, path string) []ValidationError {
	n, ok := value.(float64)
	if !ok {
		return nil
	}

	var errs []ValidationError

	if schema.Minimum != nil && n < *schema.Minimum {
		errs = append(errs, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v is less than minimum %v", n, *schema.Minimum),
		})
	}

	if schema.Maximum != nil && n > *schema.Maximum {
		errs = append(errs, ValidationError{
			Path:    path,
			Message: fmt.Sprintf("value %v is greater than maximum %v", n, *schema.Maximum),
		})
	}

	return errs
}

var dateTimePattern = regexp.MustCompile(
	`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$`,
)

func isValidDateTime(s string) bool {
	return dateTimePattern.MatchString(s)
}

func joinPath(base, field string) string {
	if base == "" {
		return field
	}
	return base + "." + field
}

func loadSchema(path string) (*Schema, error) {
	data, err := readUserJSONFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading schema: %w", err)
	}
	var s Schema
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parsing schema: %w", err)
	}
	return &s, nil
}

func loadDocument(path string) (interface{}, error) {
	data, err := readUserJSONFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading document: %w", err)
	}
	var doc interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing document: %w", err)
	}
	return doc, nil
}

type allMapping struct {
	schema   string
	examples []string
}

func findSpecDir() (string, error) {
	candidates := []string{
		"spec/mission-governance/v0alpha1",
		"VIBAP/spec/mission-governance/v0alpha1",
	}
	for _, c := range candidates {
		if info, err := os.Stat(c); err == nil && info.IsDir() {
			return c, nil
		}
	}
	return "", fmt.Errorf("cannot find spec/mission-governance/v0alpha1 directory; run from repository root or VIBAP/")
}

func buildAllMappings(specDir string) []allMapping {
	return []allMapping{
		{
			schema: filepath.Join(specDir, "declaration.schema.json"),
			examples: []string{
				filepath.Join(specDir, "examples", "declaration-code-review.json"),
				filepath.Join(specDir, "examples", "declaration-data-analysis.json"),
			},
		},
		{
			schema: filepath.Join(specDir, "event.schema.json"),
			examples: []string{
				filepath.Join(specDir, "examples", "event-compliant-read.json"),
				filepath.Join(specDir, "examples", "event-violation-exfiltration.json"),
				filepath.Join(specDir, "examples", "event-partial-visibility.json"),
			},
		},
		{
			schema: filepath.Join(specDir, "decision.schema.json"),
			examples: []string{
				filepath.Join(specDir, "examples", "decision-compliant.json"),
				filepath.Join(specDir, "examples", "decision-violation.json"),
				filepath.Join(specDir, "examples", "decision-unknown.json"),
			},
		},
		{
			schema: filepath.Join(specDir, "session.schema.json"),
			examples: []string{
				filepath.Join(specDir, "examples", "session-active.json"),
			},
		},
	}
}

func runAll() int {
	specDir, err := findSpecDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 1
	}

	mappings := buildAllMappings(specDir)
	totalDocs := 0
	totalErrors := 0

	for _, m := range mappings {
		schema, err := loadSchema(m.schema)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error loading schema %s: %v\n", m.schema, err)
			totalErrors++
			continue
		}
		schemaDir := filepath.Dir(m.schema)
		v := NewValidator(schema, schemaDir)

		for _, exPath := range m.examples {
			totalDocs++
			doc, err := loadDocument(exPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "  FAIL %s: %v\n", exPath, err)
				totalErrors++
				continue
			}
			errs := v.Validate(doc)
			if len(errs) > 0 {
				fmt.Fprintf(os.Stderr, "  FAIL %s against %s:\n", filepath.Base(exPath), filepath.Base(m.schema))
				for _, e := range errs {
					fmt.Fprintf(os.Stderr, "    - %s\n", e)
				}
				totalErrors++
			} else {
				fmt.Printf("  OK   %s against %s\n", filepath.Base(exPath), filepath.Base(m.schema))
			}
		}
	}

	fmt.Printf("\n%d documents validated, %d failed\n", totalDocs, totalErrors)
	if totalErrors > 0 {
		return 1
	}
	return 0
}

func main() {
	schemaPath := flag.String("schema", "", "Path to JSON Schema file")
	all := flag.Bool("all", false, "Validate all examples against their matching schemas")
	flag.Parse()

	if *all {
		os.Exit(runAll())
	}

	if *schemaPath == "" {
		fmt.Fprintln(os.Stderr, "usage: specvalidate --schema <schema.json> <doc.json>...")
		fmt.Fprintln(os.Stderr, "       specvalidate --all")
		os.Exit(1)
	}

	docs := flag.Args()
	if len(docs) == 0 {
		fmt.Fprintln(os.Stderr, "error: provide at least one document to validate")
		os.Exit(1)
	}

	schema, err := loadSchema(*schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	schemaDir := filepath.Dir(*schemaPath)
	v := NewValidator(schema, schemaDir)
	exitCode := 0

	for _, docPath := range docs {
		doc, err := loadDocument(docPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL %s: %v\n", docPath, err)
			exitCode = 1
			continue
		}

		errs := v.Validate(doc)
		if len(errs) > 0 {
			fmt.Fprintf(os.Stderr, "FAIL %s:\n", docPath)
			for _, e := range errs {
				fmt.Fprintf(os.Stderr, "  - %s\n", e)
			}
			exitCode = 1
		} else {
			fmt.Printf("OK   %s\n", docPath)
		}
	}

	os.Exit(exitCode)
}
