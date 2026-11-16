package rootca

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const stateVersion = 1

// state is state.json (Plan ruling 6).
type state struct {
	Version   int      `json:"version"`
	CRLNumber int64    `json:"crl_number"`
	Issued    []issued `json:"issued"`
}

// issued is one intermediate the tool signed. Key is the subject key
// identifier in hex, DER is base64 in the file.
type issued struct {
	Serial     string    `json:"serial"`
	Thumbprint string    `json:"thumbprint"`
	Name       string    `json:"name"`
	Key        string    `json:"key"`
	DER        []byte    `json:"der"`
	NotAfter   time.Time `json:"not_after"`
	Revoked    bool      `json:"revoked"`
}

func loadState(dir string) (*state, error) {
	b, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil {
		return nil, fmt.Errorf("rootca: read state.json: %w", err)
	}
	var s state
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("rootca: parse state.json: %w", err)
	}
	if s.Version != stateVersion {
		return nil, fmt.Errorf("rootca: state.json has version %d, want %d", s.Version, stateVersion)
	}
	return &s, nil
}

func saveState(dir string, s *state) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(dir, "state.json"), append(b, '\n'))
}

// writeFileAtomic replaces path through a temporary file in the same
// directory and os.Rename.
func writeFileAtomic(path string, data []byte) (err error) {
	f, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("rootca: write %s: %w", path, err)
	}
	tmp := f.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		return fmt.Errorf("rootca: write %s: %w", path, err)
	}
	return nil
}
