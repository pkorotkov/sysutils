package winutils

import "testing"

func TestGetOSProcessesEx(t *testing.T) {
	n := 100
	for i := 0; i < n; i++ {
		_, err := GetOSProcesses()
		if err != nil {
			t.Error(err)
		}
		/*
			for _, p := range ps {
				fmt.Println(p.PID, p.CommandLine)
			}
		*/
	}
}
