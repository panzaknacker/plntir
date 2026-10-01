package aianalyzer

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"plntir/core/internal/aitelemetry"
)

const (
	SchemaVersion     = 1
	ClassifierVersion = "plntir-re2-v1"
	maximumRules      = 512
)

var safeCode = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,127}$`)

type Rule struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	Severity    string   `json:"severity"`
	SummaryCode string   `json:"summary_code"`
	Pattern     string   `json:"pattern"`
	Targets     []string `json:"targets"`
}

type Bundle struct {
	SchemaVersion     int    `json:"schema_version"`
	ClassifierVersion string `json:"classifier_version"`
	RulesVersion      string `json:"rules_version"`
	IssuedAt          string `json:"issued_at"`
	ExpiresAt         string `json:"expires_at"`
	Rules             []Rule `json:"rules"`
	Signature         string `json:"signature"`
}

type Finding struct {
	RuleID      string
	Kind        string
	Severity    string
	SummaryCode string
}

type Result struct {
	ClassifierVersion string
	RulesVersion      string
	Findings          []Finding
}

type compiledRule struct {
	rule    Rule
	pattern *regexp.Regexp
	targets map[string]struct{}
}

type Analyzer struct {
	classifierVersion string
	rulesVersion      string
	rules             []compiledRule
}

func Sign(bundle *Bundle, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return errors.New("AI rule signing key is invalid")
	}
	if err := validateBundle(*bundle, time.Time{}, false); err != nil {
		return err
	}
	bundle.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, canonicalUnsigned(*bundle)))
	return nil
}

func Marshal(bundle Bundle) ([]byte, error) {
	if bundle.Signature == "" {
		return nil, errors.New("AI rule bundle is unsigned")
	}
	return json.Marshal(bundle)
}

func Load(encoded []byte, publicKey ed25519.PublicKey, now time.Time) (*Analyzer, error) {
	if len(encoded) == 0 || len(encoded) > 1<<20 || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("AI rule bundle or verification key is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	var bundle Bundle
	if err := decoder.Decode(&bundle); err != nil {
		return nil, errors.New("AI rule bundle encoding is invalid")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("AI rule bundle has trailing data")
	}
	canonical, err := json.Marshal(bundle)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, errors.New("AI rule bundle is not canonical JSON")
	}
	if err := validateBundle(bundle, now.UTC(), true); err != nil {
		return nil, err
	}
	signature, err := base64.RawURLEncoding.Strict().DecodeString(bundle.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize ||
		base64.RawURLEncoding.EncodeToString(signature) != bundle.Signature ||
		!ed25519.Verify(publicKey, canonicalUnsigned(bundle), signature) {
		return nil, errors.New("AI rule bundle signature is invalid")
	}
	analyzer := &Analyzer{classifierVersion: bundle.ClassifierVersion, rulesVersion: bundle.RulesVersion,
		rules: make([]compiledRule, 0, len(bundle.Rules))}
	for _, rule := range bundle.Rules {
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil || pattern.MatchString("") {
			return nil, errors.New("AI rule pattern is invalid")
		}
		targets := make(map[string]struct{}, len(rule.Targets))
		for _, target := range rule.Targets {
			targets[target] = struct{}{}
		}
		analyzer.rules = append(analyzer.rules, compiledRule{rule: rule, pattern: pattern, targets: targets})
	}
	return analyzer, nil
}

func (analyzer *Analyzer) Analyze(record aitelemetry.Record) (Result, error) {
	if analyzer == nil || analyzer.classifierVersion == "" || len(analyzer.rules) == 0 {
		return Result{}, errors.New("AI analyzer is not initialized")
	}
	if err := aitelemetry.Validate(record); err != nil {
		return Result{}, err
	}
	result := Result{ClassifierVersion: analyzer.classifierVersion, RulesVersion: analyzer.rulesVersion}
	for _, compiled := range analyzer.rules {
		matched := false
		for _, message := range record.Messages {
			if !message.ContentAvailable {
				continue
			}
			contentTarget := "message-content"
			if message.Role == "user" || message.Role == "system" {
				contentTarget = "prompt"
			} else if message.Role == "assistant" {
				contentTarget = "response"
			}
			if compiled.matches(contentTarget, message.Content) {
				matched = true
			}
			for _, call := range message.ToolCalls {
				if compiled.matches("tool-arguments", string(call.Arguments)) ||
					(call.OutputAvailable && compiled.matches("tool-output", call.Output)) {
					matched = true
				}
			}
			for _, attachment := range message.Attachments {
				if compiled.matches("attachment-text", attachment.ExtractedText) {
					matched = true
				}
			}
			if matched {
				break
			}
		}
		if matched {
			result.Findings = append(result.Findings, Finding{RuleID: compiled.rule.ID, Kind: compiled.rule.Kind,
				Severity: compiled.rule.Severity, SummaryCode: compiled.rule.SummaryCode})
		}
	}
	return result, nil
}

func (rule compiledRule) matches(target, value string) bool {
	if value == "" {
		return false
	}
	if _, enabled := rule.targets[target]; !enabled {
		if _, enabled = rule.targets["all-content"]; !enabled {
			return false
		}
	}
	return rule.pattern.MatchString(value)
}

func validateBundle(bundle Bundle, now time.Time, checkTime bool) error {
	if bundle.SchemaVersion != SchemaVersion || bundle.ClassifierVersion != ClassifierVersion ||
		!safeCode.MatchString(bundle.RulesVersion) || len(bundle.Rules) == 0 || len(bundle.Rules) > maximumRules {
		return errors.New("AI rule bundle metadata is invalid")
	}
	issuedAt, err := time.Parse(time.RFC3339Nano, bundle.IssuedAt)
	if err != nil || issuedAt.Year() < 2020 {
		return errors.New("AI rule issue time is invalid")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, bundle.ExpiresAt)
	if err != nil || !expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > 90*24*time.Hour {
		return errors.New("AI rule expiry is invalid")
	}
	if checkTime && (now.Before(issuedAt.Add(-5*time.Minute)) || !now.Before(expiresAt)) {
		return errors.New("AI rule bundle is not currently valid")
	}
	seen := make(map[string]struct{}, len(bundle.Rules))
	priorID := ""
	for _, rule := range bundle.Rules {
		if !safeCode.MatchString(rule.ID) || !safeCode.MatchString(rule.Kind) || !safeCode.MatchString(rule.SummaryCode) ||
			!validSeverity(rule.Severity) || len(rule.Pattern) == 0 || len(rule.Pattern) > 4096 ||
			len(rule.Targets) == 0 || len(rule.Targets) > 6 || (priorID != "" && rule.ID <= priorID) {
			return errors.New("AI rule is invalid or rules are not strictly sorted")
		}
		if _, exists := seen[rule.ID]; exists {
			return errors.New("AI rule id is duplicated")
		}
		seen[rule.ID] = struct{}{}
		priorID = rule.ID
		targetSeen := map[string]struct{}{}
		for _, target := range rule.Targets {
			if !validTarget(target) {
				return errors.New("AI rule target is invalid")
			}
			if _, exists := targetSeen[target]; exists {
				return errors.New("AI rule target is duplicated")
			}
			targetSeen[target] = struct{}{}
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return errors.New("AI rule pattern does not compile")
		}
	}
	return nil
}

func canonicalUnsigned(bundle Bundle) []byte {
	bundle.Signature = ""
	encoded, _ := json.Marshal(struct {
		SchemaVersion     int    `json:"schema_version"`
		ClassifierVersion string `json:"classifier_version"`
		RulesVersion      string `json:"rules_version"`
		IssuedAt          string `json:"issued_at"`
		ExpiresAt         string `json:"expires_at"`
		Rules             []Rule `json:"rules"`
	}{bundle.SchemaVersion, bundle.ClassifierVersion, bundle.RulesVersion, bundle.IssuedAt, bundle.ExpiresAt, bundle.Rules})
	return append([]byte("plntir-ai-rules-v1\x00"), encoded...)
}

func validSeverity(value string) bool {
	return value == "info" || value == "low" || value == "medium" || value == "high" || value == "critical"
}

func validTarget(value string) bool {
	return value == "prompt" || value == "response" || value == "message-content" || value == "tool-arguments" ||
		value == "tool-output" || value == "attachment-text" || value == "all-content"
}

func NewBundle(rulesVersion string, issuedAt, expiresAt time.Time, rules []Rule) Bundle {
	copyOfRules := append([]Rule(nil), rules...)
	for index := range copyOfRules {
		copyOfRules[index].Targets = append([]string(nil), copyOfRules[index].Targets...)
		sort.Strings(copyOfRules[index].Targets)
	}
	sort.Slice(copyOfRules, func(i, j int) bool { return strings.Compare(copyOfRules[i].ID, copyOfRules[j].ID) < 0 })
	return Bundle{SchemaVersion: SchemaVersion, ClassifierVersion: ClassifierVersion, RulesVersion: rulesVersion,
		IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano), ExpiresAt: expiresAt.UTC().Format(time.RFC3339Nano), Rules: copyOfRules}
}
