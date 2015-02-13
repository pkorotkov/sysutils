package winutils

/*
#include "winapiutils.h"
*/
import "C"

import (
    "fmt"
    "time"
)

func GetSystemStartTime() (time.Time, error) {
    var ut C.ULONGLONG = C.GetTickCount64()
    if ut == 0 {
        return time.Time{}, fmt.Errorf("failed to retrieve uptime value")
    }
    return time.Now().Add(-time.Duration(ut) * time.Millisecond), nil
}
