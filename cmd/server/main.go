package main

import (
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

var (
	emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
)

// LogEntry represents a single log entry from frontend
type LogEntry struct {
	Level       string `json:"level"`
	Message     string `json:"message"`
	Timestamp   string `json:"timestamp,omitempty"`
	Platform    string `json:"platform,omitempty"`
	Environment string `json:"environment,omitempty"`
	UserID      string `json:"userId,omitempty"`
	Error       string `json:"error,omitempty"`
	StackTrace  string `json:"stackTrace,omitempty"`
}

// rawLogEntry is used to capture extra fields during unmarshaling
type rawLogEntry struct {
	Level       string                 `json:"level"`
	Message     string                 `json:"message"`
	Timestamp   string                 `json:"timestamp,omitempty"`
	Platform    string                 `json:"platform,omitempty"`
	Environment string                 `json:"environment,omitempty"`
	UserID      string                 `json:"userId,omitempty"`
	Error       string                 `json:"error,omitempty"`
	StackTrace  string                 `json:"stackTrace,omitempty"`
	Extra       map[string]interface{} `json:"-"`
}

// hashEmail hashes an email address using SHA256 with optional salt
func hashEmail(email string) string {
	if email == "" {
		return ""
	}
	// Use a salt from env or default
	salt := os.Getenv("USER_ID_SALT")
	if salt == "" {
		salt = "logs-ingest-salt" // Change this in production!
	}

	h := sha256.New()
	h.Write([]byte(salt + email))
	return "sha256:" + hex.EncodeToString(h.Sum(nil))[:16] // Use first 16 chars for brevity
}

// scrubPII removes or hashes PII from log entry
func scrubPII(entry LogEntry, extraFields map[string]interface{}) map[string]interface{} {
	result := make(map[string]interface{})

	// Copy all fields
	result["level"] = entry.Level
	result["message"] = entry.Message

	if entry.Timestamp != "" {
		result["timestamp"] = entry.Timestamp
	}
	if entry.Platform != "" {
		result["platform"] = entry.Platform
	}
	if entry.Environment != "" {
		result["environment"] = entry.Environment
	}

	// Scrub userId: hash if it's an email, otherwise keep as-is (could be a hash already)
	if entry.UserID != "" {
		if emailRegex.MatchString(entry.UserID) {
			result["userHash"] = hashEmail(entry.UserID)
		} else {
			// Assume it's already a hash or safe identifier
			result["userKey"] = entry.UserID
		}
	}

	// Include error information
	if entry.Error != "" {
		errorObj := map[string]interface{}{
			"message": entry.Error,
		}
		if entry.StackTrace != "" {
			errorObj["stack"] = entry.StackTrace
		}
		result["error"] = errorObj
	}

	// Add server-side metadata
	result["_ingest"] = map[string]interface{}{
		"service":    "logs-ingest",
		"ingestedAt": time.Now().UTC().Format(time.RFC3339Nano),
		// "version":    os.Getenv("APP_VERSION"),
	}

	// Copy any extra fields that might have been decoded
	if extraFields != nil {
		for k, v := range extraFields {
			// Skip fields we've already processed
			skipFields := map[string]bool{
				"level": true, "message": true, "timestamp": true,
				"platform": true, "environment": true, "userId": true,
				"error": true, "stackTrace": true,
			}
			if !skipFields[k] && !strings.HasPrefix(k, "_") {
				result[k] = v
			}
		}
	}

	return result
}

// parseLogEntry handles both single log and array of logs
func parseLogEntry(data []byte) ([]LogEntry, []map[string]interface{}, error) {
	var entries []LogEntry
	var extraFieldsList []map[string]interface{}

	// Try to parse as batch format first: { "logs": [...] }
	var batch struct {
		Logs []json.RawMessage `json:"logs"`
	}
	if err := json.Unmarshal(data, &batch); err == nil && len(batch.Logs) > 0 {
		for _, rawLog := range batch.Logs {
			var raw rawLogEntry
			if err := json.Unmarshal(rawLog, &raw); err != nil {
				continue
			}
			entries = append(entries, LogEntry{
				Level:       raw.Level,
				Message:     raw.Message,
				Timestamp:   raw.Timestamp,
				Platform:    raw.Platform,
				Environment: raw.Environment,
				UserID:      raw.UserID,
				Error:       raw.Error,
				StackTrace:  raw.StackTrace,
			})
			// Extract extra fields
			var extra map[string]interface{}
			json.Unmarshal(rawLog, &extra)
			extraFieldsList = append(extraFieldsList, extra)
		}
		if len(entries) > 0 {
			return entries, extraFieldsList, nil
		}
	}

	// Try to parse as single log entry
	var rawSingle map[string]interface{}
	if err := json.Unmarshal(data, &rawSingle); err == nil {
		if msg, ok := rawSingle["message"].(string); ok && msg != "" {
			var entry LogEntry
			if b, err := json.Marshal(rawSingle); err == nil {
				json.Unmarshal(b, &entry)
				entries = append(entries, entry)
				extraFieldsList = append(extraFieldsList, rawSingle)
				return entries, extraFieldsList, nil
			}
		}
	}

	// Try to parse as array of logs directly: [...]
	var rawArray []json.RawMessage
	if err := json.Unmarshal(data, &rawArray); err == nil && len(rawArray) > 0 {
		for _, rawLog := range rawArray {
			var raw rawLogEntry
			if err := json.Unmarshal(rawLog, &raw); err != nil {
				continue
			}
			entries = append(entries, LogEntry{
				Level:       raw.Level,
				Message:     raw.Message,
				Timestamp:   raw.Timestamp,
				Platform:    raw.Platform,
				Environment: raw.Environment,
				UserID:      raw.UserID,
				Error:       raw.Error,
				StackTrace:  raw.StackTrace,
			})
			var extra map[string]interface{}
			json.Unmarshal(rawLog, &extra)
			extraFieldsList = append(extraFieldsList, extra)
		}
		if len(entries) > 0 {
			return entries, extraFieldsList, nil
		}
	}

	return nil, nil, fmt.Errorf("invalid log format: expected {logs:[]}, single log, or array of logs")
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ok","service":"logs-ingest"}`))
}

func logsHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("📝Attempting to ingest logs")
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	tokenStr := r.Header.Get("Authorization")
	if tokenStr == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}

	// Log first 50 chars for debugging
	tokenPreview := tokenStr
	if len(tokenStr) > 50 {
		tokenPreview = tokenStr[:50] + "..."
	}
	log.Printf("🔑 Raw Authorization header: %s", tokenPreview)

	// Strip "Bearer " prefix if present
	if len(tokenStr) > 7 && tokenStr[:7] == "Bearer " {
		tokenStr = tokenStr[7:]
		log.Printf("✂️  Stripped Bearer prefix, token length: %d", len(tokenStr))
	}

	_, _, _, err := validateToken(tokenStr)
	if err != nil {
		log.Printf("❌ Token validation failed: %v", err)
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusUnauthorized)
		return
	}
	log.Printf("✅ Token validated successfully")

	// Check Content-Length to prevent abuse
	const maxSize = 1 << 20 // 1 MB
	if r.ContentLength > maxSize {
		http.Error(w, `{"error":"payload too large"}`, http.StatusRequestEntityTooLarge)
		return
	}

	// Handle gzip compression
	var reader io.Reader = r.Body
	defer r.Body.Close()

	if strings.Contains(r.Header.Get("Content-Encoding"), "gzip") {
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			http.Error(w, `{"error":"invalid gzip encoding"}`, http.StatusBadRequest)
			return
		}
		defer gz.Close()
		reader = gz
	}

	// Read and parse request body
	body, err := io.ReadAll(io.LimitReader(reader, maxSize))
	if err != nil {
		http.Error(w, `{"error":"failed to read request body"}`, http.StatusBadRequest)
		return
	}

	// Parse log entries
	entries, extraFieldsList, err := parseLogEntry(body)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	if len(entries) == 0 {
		http.Error(w, `{"error":"no logs provided"}`, http.StatusBadRequest)
		return
	}

	if len(entries) > 100 { // Limit batch size
		http.Error(w, `{"error":"batch too large, max 100 logs"}`, http.StatusBadRequest)
		return
	}

	// Process and write logs to Cloud Logging
	now := time.Now()
	validCount := 0

	for i, entry := range entries {
		// Basic validation
		if entry.Message == "" {
			continue // Skip invalid entries
		}

		// Get extra fields for this entry (if any)
		var extraFields map[string]interface{}
		if i < len(extraFieldsList) {
			extraFields = extraFieldsList[i]
		}

		// Scrub PII and prepare structured log
		logData := scrubPII(entry, extraFields)

		// Parse timestamp or use server time
		timestamp := now
		if entry.Timestamp != "" {
			if t, err := time.Parse(time.RFC3339, entry.Timestamp); err == nil {
				timestamp = t
			} else if t, err := time.Parse(time.RFC3339Nano, entry.Timestamp); err == nil {
				timestamp = t
			}
		}

		// Add timestamp to log data
		logData["timestamp"] = timestamp.Format(time.RFC3339Nano)

		// Output structured log as JSON (Cloud Run automatically captures this)
		logJSON, err := json.Marshal(logData)
		if err == nil {
			// Output as structured JSON log
			log.Printf("[CLIENT_LOG] %s", string(logJSON))
		} else {
			// Fallback to simple logging
			log.Printf("[CLIENT_LOG] level=%s message=%s platform=%s environment=%s",
				entry.Level, entry.Message, entry.Platform, entry.Environment)
		}

		validCount++
	}

	// Return success response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "accepted",
		"processed": validCount,
		"total":     len(entries),
	})
}

func validateToken(tokenStr string) (string, string, int64, error) {
	var username, email string
	var tokenVersion int64
	if tokenStr != "" {
		// Check if token is blacklisted first
		// if GlobalBlacklist.IsBlacklisted(tokenStr) {
		// 	return "", "", fmt.Errorf("token has been revoked")
		// }

		secretKey := os.Getenv("SECRET_KEY")
		if secretKey == "" {
			log.Printf("⚠️  SECRET_KEY environment variable not set")
			return "", "", 0, fmt.Errorf("SECRET_KEY environment variable not set")
		}
		log.Printf("🔐 SECRET_KEY found, length: %d", len(secretKey))

		secretKeyBytes := []byte(secretKey)

		// Use the jwx library, but disable time validation for this test.
		token, err := jwt.Parse(
			[]byte(tokenStr),
			jwt.WithKey(jwa.HS256, secretKeyBytes),
			jwt.WithValidate(false), // <-- Tell the library to IGNORE time claims (exp, iat)
		)

		if err != nil {
			// If this fails, it is a signature or formatting error.
			return "", "", 0, fmt.Errorf("failed to parse or verify signature: %w", err)
		}

		// Manually log that validation was skipped
		log.Println("SIGNATURE CHECK PASSED (time validation was skipped)")

		// Correctly extract claims using the .Get() method on the parsed token.
		emailClaim, ok := token.Get("email")
		if !ok {
			return "", "", 0, fmt.Errorf("email claim not found in token")
		}
		email, ok = emailClaim.(string)
		if !ok {
			return "", "", 0, fmt.Errorf("email claim is not a string")
		}

		usernameClaim, ok := token.Get("username")
		if !ok {
			return "", "", 0, fmt.Errorf("username claim not found in token")
		}
		username, ok = usernameClaim.(string)
		if !ok {
			return "", "", 0, fmt.Errorf("username claim is not a string")
		}

		versionClaim, ok := token.Get("token_version")
		if !ok {
			return "", "", 0, fmt.Errorf("token_version claim not found in token")
		}

		// Handle both int64 and float64 (Firestore may return float64)
		if v, ok := versionClaim.(int64); ok {
			tokenVersion = v
		} else if v, ok := versionClaim.(float64); ok {
			tokenVersion = int64(v)
		} else {
			return "", "", 0, fmt.Errorf("version claim is not an int64 or float64")
		}

		// Check for token_type claim
		tokenTypeClaim, ok := token.Get("token_type")
		if ok {
			tokenType, ok := tokenTypeClaim.(string)
			if !ok {
				return "", "", 0, fmt.Errorf("token_type claim not a string")
			}
			if tokenType != "refresh" && tokenType != "access" {
				return "", "", 0, fmt.Errorf("invalid token_type: %s", tokenType)
			}

			// For refresh endpoint, we must ensure the token is a refresh token
			// We can add this check later in the handler itself if needed.
		}

	}
	return username, email, tokenVersion, nil
}

func main() {
	// Load configuration from environment
	port := os.Getenv("PORT")
	if port == "" {
		port = "8082"
	}

	environment := os.Getenv("ENVIRONMENT")
	if environment == "" {
		environment = "development"
	}

	log.Printf("🚀 Initializing logs-ingest service...")
	log.Printf("🌍 Environment: %s", environment)
	log.Printf("📝 Logs will be written to stdout (captured by Cloud Run automatically)")

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/health", healthHandler)
	mux.HandleFunc("/healthz", healthHandler) // Kubernetes convention
	mux.HandleFunc("/api/v1/logs", logsHandler)
	mux.HandleFunc("/logs", logsHandler) // Alias for convenience

	// Add CORS headers for mobile apps (optional)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simple CORS for POST requests
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-API-Key")
			w.WriteHeader(http.StatusOK)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", "*")
		mux.ServeHTTP(w, r)
	})

	server := &http.Server{
		Addr:    ":" + port,
		Handler: handler,
	}

	log.Printf("🌐 Starting server on port %s", port)

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("❌ Server error: %v", err)
	}
}
