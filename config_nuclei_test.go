package nucleisdk

import (
	"reflect"
	"testing"

	"github.com/projectdiscovery/nuclei/v3/pkg/types"
)

func TestApplyScanOptionsToNucleiOpts(t *testing.T) {
	base := &types.Options{
		Tags:        []string{"base"},
		ExcludeTags: []string{"base-ex"},
		IncludeIds:  []string{"base-id"},
		ExcludeIds:  []string{"base-ex-id"},
		Authors:     []string{"base-author"},
	}
	baseTags := []string(base.Tags)

	scan := &ScanOptions{
		Tags:        []string{"scan"},
		ExcludeTags: []string{"scan-ex"},
		TemplateIDs: []string{"scan-id"},
		ExcludeIDs:  []string{"scan-ex-id"},
		Authors:     []string{"scan-author"},
	}

	updated := applyScanOptionsToNucleiOpts(base, scan)

	if !reflect.DeepEqual([]string(base.Tags), baseTags) {
		t.Fatalf("base Tags mutated: %#v", base.Tags)
	}
	if !reflect.DeepEqual([]string(updated.Tags), []string{"scan"}) {
		t.Fatalf("updated Tags not applied: %#v", updated.Tags)
	}
	if !reflect.DeepEqual([]string(updated.ExcludeTags), []string{"scan-ex"}) {
		t.Fatalf("updated ExcludeTags not applied: %#v", updated.ExcludeTags)
	}
	if !reflect.DeepEqual([]string(updated.IncludeIds), []string{"scan-id"}) {
		t.Fatalf("updated IncludeIds not applied: %#v", updated.IncludeIds)
	}
	if !reflect.DeepEqual([]string(updated.ExcludeIds), []string{"scan-ex-id"}) {
		t.Fatalf("updated ExcludeIds not applied: %#v", updated.ExcludeIds)
	}
	if !reflect.DeepEqual([]string(updated.Authors), []string{"scan-author"}) {
		t.Fatalf("updated Authors not applied: %#v", updated.Authors)
	}
}
