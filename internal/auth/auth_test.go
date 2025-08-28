package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name          string
		headers       http.Header
		expectedKey   string
		expectedError string
	}{
		{
			name:          "valid API key",
			headers:       http.Header{"Authorization": []string{"ApiKey test-api-key-123"}},
			expectedKey:   "test-api-key-123",
			expectedError: "",
		},
		{
			name:          "no authorization header",
			headers:       http.Header{},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "empty authorization header",
			headers:       http.Header{"Authorization": []string{""}},
			expectedKey:   "",
			expectedError: "no authorization header included",
		},
		{
			name:          "malformed header - no space",
			headers:       http.Header{"Authorization": []string{"ApiKeytest-key"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "malformed header - wrong prefix",
			headers:       http.Header{"Authorization": []string{"Bearer test-key"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "malformed header - only prefix",
			headers:       http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:   "",
			expectedError: "malformed authorization header",
		},
		{
			name:          "valid key with multiple spaces",
			headers:       http.Header{"Authorization": []string{"ApiKey test-key with-spaces"}},
			expectedKey:   "test-key",
			expectedError: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if key != tt.expectedKey {
				t.Errorf("expected key %q, got %q", tt.expectedKey, key)
			}

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error %q, got nil", tt.expectedError)
				} else if err.Error() != tt.expectedError {
					t.Errorf("expected error %q, got %q", tt.expectedError, err.Error())
				}
			}
		})
	}
}
