module github.com/prometheus-community/windows_exporter

go 1.13

require (
	github.com/Microsoft/hcsshim v0.9.3
	github.com/StackExchange/wmi v0.0.0-20180725035823-b12b22c5341f
	github.com/dimchansky/utfbom v1.1.1
	github.com/go-kit/log v0.2.1
	github.com/go-ole/go-ole v1.2.6
	github.com/leoluk/perflib_exporter v0.1.1-0.20211204221052-9e3696429c20
	github.com/prometheus/client_golang v1.12.2
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/common v0.35.0
	github.com/prometheus/exporter-toolkit v0.7.1
	github.com/shirou/gopsutil v3.21.11+incompatible
	github.com/sirupsen/logrus v1.8.1
	github.com/tklauser/go-sysconf v0.3.10 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	golang.org/x/sys v0.0.0-20220128215802-99c3d69c2c27
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
	gopkg.in/yaml.v2 v2.4.0
)
