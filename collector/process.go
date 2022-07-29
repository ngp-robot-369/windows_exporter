//go:build windows
// +build windows

package collector

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/StackExchange/wmi"
	"github.com/prometheus-community/windows_exporter/log"
	"github.com/prometheus-community/windows_exporter/patches/ngp"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	NGP_NODE_ID    = "node_id"
	NGP_OBJECT_ID  = "object_id"
	socketScanLast = time.Time{}
	socketMap      = map[string]int{}
)

func init() {
	registerCollector("process", newProcessCollector, "Process")
}

var (
	processWhitelist = kingpin.Flag(
		"collector.process.whitelist",
		"Regexp of processes to include. Process name must both match whitelist and not match blacklist to be included.",
	).Default(".*").String()
	processBlacklist = kingpin.Flag(
		"collector.process.blacklist",
		"Regexp of processes to exclude. Process name must both match whitelist and not match blacklist to be included.",
	).Default("").String()
)

type processCollector struct {
	StartTime         *prometheus.Desc
	CPUTimeTotal      *prometheus.Desc
	HandleCount       *prometheus.Desc
	IOBytesTotal      *prometheus.Desc
	IOOperationsTotal *prometheus.Desc
	PageFaultsTotal   *prometheus.Desc
	PageFileBytes     *prometheus.Desc
	PoolBytes         *prometheus.Desc
	PriorityBase      *prometheus.Desc
	PrivateBytes      *prometheus.Desc
	ThreadCount       *prometheus.Desc
	VirtualBytes      *prometheus.Desc
	WorkingSetPrivate *prometheus.Desc
	WorkingSetPeak    *prometheus.Desc
	WorkingSet        *prometheus.Desc
	SocketsUsed       *prometheus.Desc

	processWhitelistPattern *regexp.Regexp
	processBlacklistPattern *regexp.Regexp
}

// NewProcessCollector ...
func newProcessCollector() (Collector, error) {
	const subsystem = "process"

	if *processWhitelist == ".*" && *processBlacklist == "" {
		log.Warn("No filters specified for process collector. This will generate a very large number of metrics!")
	}

	return &processCollector{
		StartTime: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "start_time"),
			"Time of process start.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		CPUTimeTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "cpu_time_total"),
			"Returns elapsed time that all of the threads of this process used the processor to execute instructions by mode (privileged, user).",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID, "mode"},
			nil,
		),
		HandleCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "handles"),
			"Total number of handles the process has open. This number is the sum of the handles currently open by each thread in the process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		IOBytesTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "io_bytes_total"),
			"Bytes issued to I/O operations in different modes (read, write, other).",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID, "mode"},
			nil,
		),
		IOOperationsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "io_operations_total"),
			"I/O operations issued in different modes (read, write, other).",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID, "mode"},
			nil,
		),
		PageFaultsTotal: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "page_faults_total"),
			"Page faults by the threads executing in this process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		PageFileBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "page_file_bytes"),
			"Current number of bytes this process has used in the paging file(s).",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		PoolBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "pool_bytes"),
			"Pool Bytes is the last observed number of bytes in the paged or nonpaged pool.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID, "pool"},
			nil,
		),
		PriorityBase: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "priority_base"),
			"Current base priority of this process. Threads within a process can raise and lower their own base priority relative to the process base priority of the process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		PrivateBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "private_bytes"),
			"Current number of bytes this process has allocated that cannot be shared with other processes.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		ThreadCount: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "threads"),
			"Number of threads currently active in this process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		VirtualBytes: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "virtual_bytes"),
			"Current size, in bytes, of the virtual address space that the process is using.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		WorkingSetPrivate: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "working_set_private_bytes"),
			"Size of the working set, in bytes, that is use for this process only and not shared nor shareable by other processes.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		WorkingSetPeak: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "working_set_peak_bytes"),
			"Maximum size, in bytes, of the Working Set of this process at any point in time. The Working Set is the set of memory pages touched recently by the threads in the process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		WorkingSet: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "working_set_bytes"),
			"Maximum number of bytes in the working set of this process at any point in time. The working set is the set of memory pages touched recently by the threads in the process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID},
			nil,
		),
		SocketsUsed: prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, "socket_count"),
			"Number of sockets used by the process.",
			[]string{"process", NGP_NODE_ID, NGP_OBJECT_ID, "type"},
			nil,
		),
		processWhitelistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *processWhitelist)),
		processBlacklistPattern: regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *processBlacklist)),
	}, nil
}

type perflibProcess struct {
	Name                    string
	PercentProcessorTime    float64 `perflib:"% Processor Time"`
	PercentPrivilegedTime   float64 `perflib:"% Privileged Time"`
	PercentUserTime         float64 `perflib:"% User Time"`
	CreatingProcessID       float64 `perflib:"Creating Process ID"`
	ElapsedTime             float64 `perflib:"Elapsed Time"`
	HandleCount             float64 `perflib:"Handle Count"`
	IDProcess               float64 `perflib:"ID Process"`
	IODataBytesPerSec       float64 `perflib:"IO Data Bytes/sec"`
	IODataOperationsPerSec  float64 `perflib:"IO Data Operations/sec"`
	IOOtherBytesPerSec      float64 `perflib:"IO Other Bytes/sec"`
	IOOtherOperationsPerSec float64 `perflib:"IO Other Operations/sec"`
	IOReadBytesPerSec       float64 `perflib:"IO Read Bytes/sec"`
	IOReadOperationsPerSec  float64 `perflib:"IO Read Operations/sec"`
	IOWriteBytesPerSec      float64 `perflib:"IO Write Bytes/sec"`
	IOWriteOperationsPerSec float64 `perflib:"IO Write Operations/sec"`
	PageFaultsPerSec        float64 `perflib:"Page Faults/sec"`
	PageFileBytesPeak       float64 `perflib:"Page File Bytes Peak"`
	PageFileBytes           float64 `perflib:"Page File Bytes"`
	PoolNonpagedBytes       float64 `perflib:"Pool Nonpaged Bytes"`
	PoolPagedBytes          float64 `perflib:"Pool Paged Bytes"`
	PriorityBase            float64 `perflib:"Priority Base"`
	PrivateBytes            float64 `perflib:"Private Bytes"`
	ThreadCount             float64 `perflib:"Thread Count"`
	VirtualBytesPeak        float64 `perflib:"Virtual Bytes Peak"`
	VirtualBytes            float64 `perflib:"Virtual Bytes"`
	WorkingSetPrivate       float64 `perflib:"Working Set - Private"`
	WorkingSetPeak          float64 `perflib:"Working Set Peak"`
	WorkingSet              float64 `perflib:"Working Set"`
}

type WorkerProcess struct {
	AppPoolName string
	ProcessId   uint64
}

func (c *processCollector) Collect(ctx *ScrapeContext, ch chan<- prometheus.Metric) error {
	data := make([]perflibProcess, 0)
	err := unmarshalObject(ctx.perfObjects["Process"], &data)
	if err != nil {
		return err
	}

	var dst_wp []WorkerProcess
	q_wp := queryAll(&dst_wp)
	if err := wmi.QueryNamespace(q_wp, &dst_wp, "root\\WebAdministration"); err != nil {
		log.Debugf("Could not query WebAdministration namespace for IIS worker processes: %v. Skipping", err)
	}

	// Prepare process list
	type ProcPerf struct {
		perflibProcess
		pid  string
		name string
	}
	var (
		procList = []ProcPerf{}
		req      = ngp.ProcReq{}
	)
	for _, process := range data {
		if process.Name == "_Total" ||
			c.processBlacklistPattern.MatchString(process.Name) ||
			!c.processWhitelistPattern.MatchString(process.Name) {
			continue
		}
		// Duplicate processes are suffixed # and an index number. Remove those.
		processName := strings.Split(process.Name, "#")[0]
		pid := strconv.FormatUint(uint64(process.IDProcess), 10)

		for _, wp := range dst_wp {
			if wp.ProcessId == uint64(process.IDProcess) {
				processName = strings.Join([]string{processName, wp.AppPoolName}, "_")
				break
			}
		}
		procList = append(procList, ProcPerf{process, pid, processName})
		req = append(req, pid)
	}

	// Prepare additional info
	objectMap, err := ngp.RequestProcObjects(req)
	if err != nil {
		log.Warn("Request ngp process objects failed: %v", err)
	}
	if time.Since(socketScanLast) > time.Minute {
		socketScanLast = time.Now()
		socketMap, err = ngp.MakeSocketsMap()
		if err != nil {
			log.Warn("Collect sockets failed: %v", err)
		}
	}

	// Push metrics
	for _, process := range procList {
		var (
			node    = ""
			object  = ""
			sockets = 0
		)
		meta, ok := objectMap[process.pid]
		if ok {
			if meta.NoExport {
				continue
			}
			node = meta.NodeID
			object = meta.Object
			sockets = socketMap[process.pid]
		}
		// each metric must have unique labels set
		if object == "" {
			object = process.name + ":" + process.pid
		}
		push := MakeProcTag(process.name, node, object)

		ch <- push.Guage(c.StartTime, process.ElapsedTime)
		ch <- push.Guage(c.HandleCount, process.HandleCount)
		ch <- push.Guage(c.PageFileBytes, process.PageFileBytes)
		ch <- push.Guage(c.PoolBytes, process.PoolNonpagedBytes, "nonpaged")
		ch <- push.Guage(c.PoolBytes, process.PoolPagedBytes, "paged")
		ch <- push.Guage(c.PriorityBase, process.PriorityBase)
		ch <- push.Guage(c.PrivateBytes, process.PrivateBytes)
		ch <- push.Guage(c.ThreadCount, process.ThreadCount)
		ch <- push.Guage(c.VirtualBytes, process.VirtualBytes)
		ch <- push.Guage(c.WorkingSetPrivate, process.WorkingSetPrivate)
		ch <- push.Guage(c.WorkingSetPeak, process.WorkingSetPeak)
		ch <- push.Guage(c.WorkingSet, process.WorkingSet)
		ch <- push.Counter(c.CPUTimeTotal, process.PercentPrivilegedTime, "privileged")
		ch <- push.Counter(c.CPUTimeTotal, process.PercentUserTime, "user")
		ch <- push.Counter(c.IOBytesTotal, process.IOOtherBytesPerSec, "other")
		ch <- push.Counter(c.IOOperationsTotal, process.IOOtherOperationsPerSec, "other")
		ch <- push.Counter(c.IOBytesTotal, process.IOReadBytesPerSec, "read")
		ch <- push.Counter(c.IOOperationsTotal, process.IOReadOperationsPerSec, "read")
		ch <- push.Counter(c.IOBytesTotal, process.IOWriteBytesPerSec, "write")
		ch <- push.Counter(c.IOOperationsTotal, process.IOWriteOperationsPerSec, "write")
		ch <- push.Counter(c.PageFaultsTotal, process.PageFaultsPerSec)

		// additional metrics
		ch <- push.Guage(c.SocketsUsed, float64(sockets), "TCP")
	}
	return nil
}

type ProcTag struct {
	name   string
	node   string
	object string
}

func MakeProcTag(name string, node string, object string) ProcTag {
	return ProcTag{name, node, object}
}

func (p *ProcTag) Counter(desk *prometheus.Desc, value float64, labels ...string) prometheus.Metric {
	labelValues := append([]string{p.name, p.node, p.object}, labels...)
	return prometheus.MustNewConstMetric(desk, prometheus.CounterValue, value, labelValues...)
}

func (p *ProcTag) Guage(desk *prometheus.Desc, value float64, labels ...string) prometheus.Metric {
	labelValues := append([]string{p.name, p.node, p.object}, labels...)
	return prometheus.MustNewConstMetric(desk, prometheus.GaugeValue, value, labelValues...)
}
