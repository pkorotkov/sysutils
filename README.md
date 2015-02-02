winutils
========

[![GoDoc](https://godoc.org/github.com/pkorotkov/winutils?status.svg)](https://godoc.org/github.com/pkorotkov/winutils)

## FYI

The library was intended to provide basic API for typical WinAPI consumers.
My early needs have not gone beyond information about OS processes, so I implemented only small part of all possible and useful queries.
Then I discovered [gopsutil](https://github.com/shirou/gopsutil), a swiss army knife cross-platform toolkit at any necessity.
Despite my library still has some unique functionality as compared to gopsutil I plan to contribute the code to gopsutil and close down this home brewery.

## Installation
```
go get -u -v github.com/pkorotkov/winutils
```

## License
MIT
