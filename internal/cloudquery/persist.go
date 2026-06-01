package cloudquery

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// SaveAll writes a full dataset to <dir>: the CloudQuery table files PLUS the
// independent answer key (answer_key.json), so the dataset can be re-loaded and
// scored exactly. This is what `--cloudquery-emit` writes for a generated
// account.
func (ds *Dataset) SaveAll(dir string) error {
	if err := ds.Tables.Save(dir); err != nil {
		return err
	}
	b, err := json.MarshalIndent(ds.AnswerKey, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "answer_key.json"), b, 0o600); err != nil {
		return fmt.Errorf("cloudquery: write answer_key.json: %w", err)
	}
	return nil
}

// LoadDataset reads a dataset directory (CloudQuery tables + answer_key.json). The
// answer key is optional — a real CloudQuery sync has no key — in which case only
// the tables are populated.
func LoadDataset(dir string) (*Dataset, error) {
	t, err := Load(dir)
	if err != nil {
		return nil, err
	}
	ds := &Dataset{Tables: t}
	if b, rerr := os.ReadFile(filepath.Join(dir, "answer_key.json")); rerr == nil {
		if jerr := json.Unmarshal(b, &ds.AnswerKey); jerr != nil {
			return nil, fmt.Errorf("cloudquery: parse answer_key.json: %w", jerr)
		}
	}
	return ds, nil
}
