package main

import "testing"

func TestReadfile(t *testing.T) {

	got := readfile("/etc/hostname")
	// want :=

	if len(got) == 0 {
		t.Errorf("got %s", got)
	}
}
