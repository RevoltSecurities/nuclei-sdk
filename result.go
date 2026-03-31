package nucleisdk

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/projectdiscovery/nuclei/v3/pkg/output"
)

// ScanResult represents a single scan finding with a clean API.
type ScanResult struct {
	// Core identification
	TemplateID   string `json:"template_id"`
	TemplateName string `json:"template_name"`
	TemplatePath string `json:"template_path,omitempty"`
	Severity     string `json:"severity"`
	Type         string `json:"type"`

	// Match details
	Host             string   `json:"host"`
	MatchedURL       string   `json:"matched_url"`
	MatcherName      string   `json:"matcher_name,omitempty"`
	ExtractorName    string   `json:"extractor_name,omitempty"`
	ExtractedResults []string `json:"extracted_results,omitempty"`
	IP               string   `json:"ip,omitempty"`
	Port             string   `json:"port,omitempty"`
	Scheme           string   `json:"scheme,omitempty"`
	URL              string   `json:"url,omitempty"`
	Path             string   `json:"path,omitempty"`

	// Request/Response
	Request     string `json:"request,omitempty"`
	Response    string `json:"response,omitempty"`
	CURLCommand string `json:"curl_command,omitempty"`

	// Metadata
	Tags        []string               `json:"tags,omitempty"`
	Authors     []string               `json:"authors,omitempty"`
	Description string                 `json:"description,omitempty"`
	Impact      string                 `json:"impact,omitempty"`
	Remediation string                 `json:"remediation,omitempty"`
	Reference   []string               `json:"reference,omitempty"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`

	// Classification
	CVEID       []string `json:"cve_id,omitempty"`
	CWEID       []string `json:"cwe_id,omitempty"`
	CVSSMetrics string   `json:"cvss_metrics,omitempty"`
	CVSSScore   float64  `json:"cvss_score,omitempty"`
	EPSSScore   float64  `json:"epss_score,omitempty"`
	CPE         string   `json:"cpe,omitempty"`

	// Fuzzing
	IsFuzzingResult  bool   `json:"is_fuzzing_result,omitempty"`
	FuzzingMethod    string `json:"fuzzing_method,omitempty"`
	FuzzingParameter string `json:"fuzzing_parameter,omitempty"`
	FuzzingPosition  string `json:"fuzzing_position,omitempty"`

	// Status
	MatcherStatus bool      `json:"matcher_status"`
	Timestamp     time.Time `json:"timestamp"`
	Error         string    `json:"error,omitempty"`

	// raw holds the original nuclei ResultEvent for advanced use
	raw *output.ResultEvent
}

// JSON returns the result serialized as a JSON string.
func (r *ScanResult) JSON() string {
	b, err := json.Marshal(r)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// JSONBytes returns the result serialized as JSON bytes.
func (r *ScanResult) JSONBytes() ([]byte, error) {
	return json.Marshal(r)
}

// JSONPretty returns the result serialized as pretty-printed JSON.
func (r *ScanResult) JSONPretty() string {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

// RawEvent returns the underlying nuclei output.ResultEvent for advanced users.
func (r *ScanResult) RawEvent() *output.ResultEvent {
	return r.raw
}

// IsCritical returns true if the severity is critical.
func (r *ScanResult) IsCritical() bool {
	return strings.EqualFold(r.Severity, "critical")
}

// IsHighOrAbove returns true if the severity is high or critical.
func (r *ScanResult) IsHighOrAbove() bool {
	level := r.SeverityLevel()
	return level >= 4
}

// SeverityLevel returns a numeric severity level.
// 0=unknown, 1=info, 2=low, 3=medium, 4=high, 5=critical
func (r *ScanResult) SeverityLevel() int {
	switch strings.ToLower(r.Severity) {
	case "info":
		return 1
	case "low":
		return 2
	case "medium":
		return 3
	case "high":
		return 4
	case "critical":
		return 5
	default:
		return 0
	}
}

// fromResultEvent converts a nuclei output.ResultEvent to a ScanResult.
func fromResultEvent(event *output.ResultEvent) *ScanResult {
	if event == nil {
		return nil
	}

	result := &ScanResult{
		TemplateID:       event.TemplateID,
		TemplateName:     event.Info.Name,
		TemplatePath:     event.TemplatePath,
		Severity:         event.Info.SeverityHolder.Severity.String(),
		Type:             event.Type,
		Host:             event.Host,
		MatchedURL:       event.Matched,
		MatcherName:      event.MatcherName,
		ExtractorName:    event.ExtractorName,
		ExtractedResults: event.ExtractedResults,
		IP:               event.IP,
		Port:             event.Port,
		Scheme:           event.Scheme,
		URL:              event.URL,
		Path:             event.Path,
		Request:          event.Request,
		Response:         event.Response,
		CURLCommand:      event.CURLCommand,
		Description:      event.Info.Description,
		Impact:           event.Info.Impact,
		Remediation:      event.Info.Remediation,
		Metadata:         event.Metadata,
		IsFuzzingResult:  event.IsFuzzingResult,
		FuzzingMethod:    event.FuzzingMethod,
		FuzzingParameter: event.FuzzingParameter,
		FuzzingPosition:  event.FuzzingPosition,
		MatcherStatus:    event.MatcherStatus,
		Timestamp:        event.Timestamp,
		Error:            event.Error,
		raw:              event,
	}

	// Tags
	if !event.Info.Tags.IsEmpty() {
		result.Tags = event.Info.Tags.ToSlice()
	}

	// Authors
	if !event.Info.Authors.IsEmpty() {
		result.Authors = event.Info.Authors.ToSlice()
	}

	// Reference
	if event.Info.Reference != nil && !event.Info.Reference.IsEmpty() {
		result.Reference = event.Info.Reference.ToSlice()
	}

	// Classification
	if event.Info.Classification != nil {
		c := event.Info.Classification
		if !c.CVEID.IsEmpty() {
			result.CVEID = c.CVEID.ToSlice()
		}
		if !c.CWEID.IsEmpty() {
			result.CWEID = c.CWEID.ToSlice()
		}
		result.CVSSMetrics = c.CVSSMetrics
		result.CVSSScore = c.CVSSScore
		result.EPSSScore = c.EPSSScore
		result.CPE = c.CPE
	}

	return result
}

// matchesSeverityFilter checks if a result matches the severity filter.
func matchesSeverityFilter(result *ScanResult, filter []string) bool {
	if len(filter) == 0 {
		return true
	}
	for _, s := range filter {
		if strings.EqualFold(result.Severity, s) {
			return true
		}
	}
	return false
}
