package winutils

import "testing"

func TestGetOSProcessesEx(t *testing.T) {
	n := 1
	for i := 0; i < n; i++ {
		_, err := GetOSProcesses()
		if err != nil {
			t.Error(err)
		}
	}
}
