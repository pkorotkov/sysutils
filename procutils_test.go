package winutils

import (
	"fmt"
	"testing"
)

func TestGetOSProcesses(t *testing.T) {
	n := 1
	for i := 0; i < n; i++ {
		ps, err := GetOSProcesses()
		if err != nil {
			t.Error(err)
		}

		for _, p := range ps {
			fmt.Println(p)
		}
	}
}
