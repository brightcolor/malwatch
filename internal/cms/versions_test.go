package cms

import (
	"reflect"
	"testing"
)

// The page "Updates" offers every published release above the installed one.
// Trunk, pre-releases and tags above the newest stable release stay out.
func TestLatestPluginInfoListsTheStableReleases(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got, want := l.LatestPluginInfo("plugin", "akismet").Versions, []string{"5.3.3", "5.3.2", "5.3", "5.1", "4.2.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("plugin releases = %v, want %v", got, want)
	}
	if got, want := l.LatestPluginInfo("theme", "twentytwentyfour").Versions, []string{"1.2", "1.1", "1.0"}; !reflect.DeepEqual(got, want) {
		t.Errorf("theme releases = %v, want %v", got, want)
	}
	// The second call comes from the cache and still carries the list.
	if got := l.LatestPluginInfo("plugin", "akismet").Versions; len(got) != 5 {
		t.Errorf("cached plugin releases = %v", got)
	}
}

func TestNewerKeepsTheReleasesAboveTheInstalledOne(t *testing.T) {
	if got, want := Newer([]string{"5.3.3", "5.3.2", "5.3", "5.1", "4.2.5"}, "5.2"), []string{"5.3.3", "5.3.2", "5.3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Newer = %v, want %v", got, want)
	}
	if got := Newer([]string{"5.1"}, "5.1"); len(got) != 0 {
		t.Errorf("the installed release itself = %v", got)
	}
}

// The core lists every newer release, on its own branch and above it.
func TestWordPressNewerListsEveryBranch(t *testing.T) {
	l := fakeWordPressOrg(t)
	if got, want := l.WordPressNewer("6.4.4"), []string{"7.1", "6.5.3", "6.4.5"}; !reflect.DeepEqual(got, want) {
		t.Errorf("WordPressNewer = %v, want %v", got, want)
	}
}
