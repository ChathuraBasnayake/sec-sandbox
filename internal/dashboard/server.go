package dashboard

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

//go:embed templates/*
var templatesFS embed.FS

// ReportSummary represents a lightweight view of a report for the dashboard index
type ReportSummary struct {
	ID          string    `json:"id"`
	PackageName string    `json:"package_name"`
	ThreatScore int       `json:"threat_score"`
	RiskLevel   string    `json:"risk_level"`
	AnalyzedAt  time.Time `json:"analyzed_at"`
	EventsTotal int       `json:"events_total"`
	Findings    int       `json:"findings"`
}

// Server handles dashboard HTTP requests
type Server struct {
	reportsDir string
	port       int
}

// New creates a new dashboard server
func New(port int) *Server {
	// Find the workspace root based on the executable or current dir
	cwd, _ := os.Getwd()
	reportsDir := filepath.Join(cwd, "reports")
	
	// Create reports directory if it doesn't exist
	os.MkdirAll(reportsDir, 0755)

	return &Server{
		reportsDir: reportsDir,
		port:       port,
	}
}

// Start begins serving the dashboard
func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API Endpoints
	mux.HandleFunc("/api/reports", s.handleListReports)
	mux.HandleFunc("/api/reports/", s.handleGetReport)

	// Serve the embedded static UI
	mux.HandleFunc("/", s.handleStaticIndex)

	addr := fmt.Sprintf(":%d", s.port)
	fmt.Printf("\n  \033[32m\033[1m✓ Dashboard running at http://localhost%s\033[0m\n", addr)
	fmt.Printf("  \033[2mServing reports from: %s\033[0m\n\n", s.reportsDir)
	
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleStaticIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	
	content, err := templatesFS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "Failed to load dashboard UI", http.StatusInternalServerError)
		return
	}
	
	w.Header().Set("Content-Type", "text/html")
	w.Write(content)
}

func (s *Server) handleListReports(w http.ResponseWriter, r *http.Request) {
	files, err := os.ReadDir(s.reportsDir)
	if err != nil {
		http.Error(w, "Failed to read reports directory", http.StatusInternalServerError)
		return
	}

	var summaries []ReportSummary

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}

		path := filepath.Join(s.reportsDir, file.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}

		// Use a flexible map to extract just what we need without needing the full schema in Go
		var raw map[string]interface{}
		if err := json.Unmarshal(data, &raw); err != nil {
			continue
		}

		// Extract fields safely
		pkgName, _ := raw["package_name"].(string)
		
		var score int
		if s, ok := raw["threat_score"].(float64); ok {
			score = int(s)
		}
		
		riskLevel, _ := raw["risk_level"].(string)
		
		var analyzedAt time.Time
		if timeStr, ok := raw["analyzed_at"].(string); ok {
			analyzedAt, _ = time.Parse(time.RFC3339, timeStr)
		}

		var events int
		if e, ok := raw["events_analyzed"].(float64); ok {
			events = int(e)
		}

		findingsCount := 0
		if findings, ok := raw["findings"].([]interface{}); ok {
			findingsCount = len(findings)
		}

		// Use the sanitized filename as the ID so the frontend can request it directly
		safeID := strings.TrimSuffix(file.Name(), ".json")

		summaries = append(summaries, ReportSummary{
			ID:          safeID,
			PackageName: pkgName,
			ThreatScore: score,
			RiskLevel:   riskLevel,
			AnalyzedAt:  analyzedAt,
			EventsTotal: events,
			Findings:    findingsCount,
		})
	}

	// Sort newest first
	sort.Slice(summaries, func(i, j int) bool {
		return summaries[i].AnalyzedAt.After(summaries[j].AnalyzedAt)
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(summaries)
}

func (s *Server) handleGetReport(w http.ResponseWriter, r *http.Request) {
	// Extract report ID from path: /api/reports/det-2026-...
	id := strings.TrimPrefix(r.URL.Path, "/api/reports/")
	if id == "" {
		http.Error(w, "Missing report ID", http.StatusBadRequest)
		return
	}

	// Sanitize to prevent directory traversal
	id = filepath.Base(id)
	if !strings.HasSuffix(id, ".json") {
		id += ".json"
	}

	path := filepath.Join(s.reportsDir, id)
	
	// Read and serve the exact JSON file
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, "Report not found", http.StatusNotFound)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
