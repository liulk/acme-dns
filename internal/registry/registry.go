package registry

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
)

type Record struct {
	AllowFrom  []string `json:"allowfrom,omitempty"`
	FullDomain string   `json:"fulldomain,omitempty"`
	Password   string   `json:"password,omitempty"`
	Subdomain  string   `json:"subdomain,omitempty"`
	Username   string   `json:"username,omitempty"`
	TXT        string   `json:"txt,omitempty"`  // for compatibility
	TXTs       []string `json:"txts,omitempty"` // preferred, overrides TXT
}

func (r *Record) PreferredTXTs() []string {
	if len(r.TXTs) > 0 {
		return r.TXTs
	}
	return []string{r.TXT}
}

var b64urle = base64.RawURLEncoding

func NewRecord(domain string) (*Record, error) {
	var r Record
	if u4, err := uuid.NewRandom(); err != nil {
		return nil, err
	} else {
		r.Subdomain = u4.String()
		r.FullDomain = r.Subdomain + "." + domain
	}
	if u4, err := uuid.NewRandom(); err != nil {
		return nil, err
	} else {
		r.Username = u4.String()
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	r.Password = b64urle.EncodeToString(b)
	return &r, nil
}

type Registry string

func (r Registry) Read(subdomain string) (recs []Record, err error) {
	var errs []error
	matches, err := filepath.Glob(filepath.Join(string(r), subdomain) + ".*")
	if err != nil {
		return nil, err
	}

	for _, match := range matches {
		if !strings.HasSuffix(match, ".json") {
			continue
		}
		b, err := os.ReadFile(match)
		if err != nil {
			errs = append(errs, err)
		}
		var rec Record
		if err := json.Unmarshal(b, &rec); err != nil {
			errs = append(errs, err)
			continue
		}
		recs = append(recs, rec)
	}

	return recs, errors.Join(errs...)
}
