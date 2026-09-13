package report

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestTheScanReportCarriesWhatAnUpgradeNeeds(t *testing.T) {
	rep := New([]string{"/w"})
	rep.PHPVersion = "8.2.10"
	rep.Software = append(rep.Software, Software{
		Path: "/w", Product: "wordpress", Kind: "core", Version: "6.4.2",
		LatestInBranch: "6.4.5", LatestRequiresPHP: "7.4",
	}, Software{
		Path: "/w/wp-content/plugins/akismet", Product: "wordpress", Kind: "plugin", Slug: "akismet",
		Version: "5.3.0", LatestRequiresWP: "6.2", LatestRequiresPHP: "7.2",
	})
	var buf bytes.Buffer
	if err := rep.WriteJSON(&buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		PHPVersion string `json:"php_version"`
		Software   []struct {
			LatestInBranch    string `json:"latest_in_branch"`
			LatestRequiresWP  string `json:"latest_requires_wp"`
			LatestRequiresPHP string `json:"latest_requires_php"`
		} `json:"software"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.PHPVersion != "8.2.10" || doc.Software[0].LatestInBranch != "6.4.5" ||
		doc.Software[1].LatestRequiresWP != "6.2" || doc.Software[1].LatestRequiresPHP != "7.2" {
		t.Errorf("report = %s", buf.String())
	}
}
