package nmap

import (
	"bytes"
	"encoding/xml"
	"io"
	"os"
	"strconv"
	"time"

	family "github.com/Ullaakut/nmap/v4/pkg/osfamilies"
)

// Run represents an nmap scanning run.
type Run struct {
	XMLName xml.Name `xml:"nmaprun"`

	Args             string         `json:"args"               xml:"args,attr"`
	ProfileName      string         `json:"profile_name"       xml:"profile_name,attr"`
	Scanner          string         `json:"scanner"            xml:"scanner,attr"`
	StartStr         string         `json:"start_str"          xml:"startstr,attr"`
	Version          string         `json:"version"            xml:"version,attr"`
	XMLOutputVersion string         `json:"xml_output_version" xml:"xmloutputversion,attr"`
	Debugging        Debugging      `json:"debugging"          xml:"debugging"`
	Stats            Stats          `json:"run_stats"          xml:"runstats"`
	ScanInfo         ScanInfo       `json:"scan_info"          xml:"scaninfo"`
	Start            Timestamp      `json:"start"              xml:"start,attr"`
	Verbose          Verbose        `json:"verbose"            xml:"verbose"`
	Hosts            []Host         `json:"hosts"              xml:"host"`
	PostScripts      []Script       `json:"post_scripts"       xml:"postscript>script"`
	PreScripts       []Script       `json:"pre_scripts"        xml:"prescript>script"`
	Targets          []Target       `json:"targets"            xml:"target"`
	TaskBegin        []Task         `json:"task_begin"         xml:"taskbegin"`
	TaskProgress     []TaskProgress `json:"task_progress"      xml:"taskprogress"`
	TaskEnd          []Task         `json:"task_end"           xml:"taskend"`

	warnings []string
	rawXML   []byte
}

// ToFile writes a Run as XML into the specified file path.
func (r *Run) ToFile(filePath string) error {
	return os.WriteFile(filePath, r.rawXML, 0o600)
}

// ToReader writes the raw XML into an streamable buffer.
func (r *Run) ToReader() io.Reader {
	return bytes.NewReader(r.rawXML)
}

// Warnings returns the warnings encountered during the nmap scan.
func (r *Run) Warnings() []string {
	return r.warnings
}

// ScanInfo represents the scan information.
type ScanInfo struct {
	NumServices int    `json:"num_services" xml:"numservices,attr"`
	Protocol    string `json:"protocol"     xml:"protocol,attr"`
	ScanFlags   string `json:"scan_flags"   xml:"scanflags,attr"`
	Services    string `json:"services"     xml:"services,attr"`
	Type        string `json:"type"         xml:"type,attr"`
}

// Verbose contains the verbosity level of the scan.
type Verbose struct {
	Level int `json:"level" xml:"level,attr"`
}

// Debugging contains the debugging level of the scan.
type Debugging struct {
	Level int `json:"level" xml:"level,attr"`
}

// Task contains information about a task.
type Task struct {
	Time      Timestamp `json:"time"       xml:"time,attr"`
	Task      string    `json:"task"       xml:"task,attr"`
	ExtraInfo string    `json:"extra_info" xml:"extrainfo,attr"`
}

// TaskProgress contains information about the progression of a task.
type TaskProgress struct {
	Percent   float32   `json:"percent"   xml:"percent,attr"`
	Remaining int       `json:"remaining" xml:"remaining,attr"`
	Task      string    `json:"task"      xml:"task,attr"`
	Etc       Timestamp `json:"etc"       xml:"etc,attr"`
	Time      Timestamp `json:"time"      xml:"time,attr"`
}

// Target represents a target, how it was specified when passed to nmap,
// its status and the reason for its status. Example:
// <target specification="domain.does.not.exist" status="skipped" reason="invalid"/>.
type Target struct {
	Specification string `json:"specification" xml:"specification,attr"`
	Status        string `json:"status"        xml:"status,attr"`
	Reason        string `json:"reason"        xml:"reason,attr"`
}

// Host represents a host that was scanned.
type Host struct {
	Distance      Distance      `json:"distance"        xml:"distance"`
	EndTime       Timestamp     `json:"end_time"        xml:"endtime,attr,omitempty"`
	IPIDSequence  IPIDSequence  `json:"ip_id_sequence"  xml:"ipidsequence"`
	OS            OS            `json:"os"              xml:"os"`
	StartTime     Timestamp     `json:"start_time"      xml:"starttime,attr,omitempty"`
	TimedOut      bool          `json:"timed_out"       xml:"timedout,attr,omitempty"`
	Status        Status        `json:"status"          xml:"status"`
	TCPSequence   TCPSequence   `json:"tcp_sequence"    xml:"tcpsequence"`
	TCPTSSequence TCPTSSequence `json:"tcp_ts_sequence" xml:"tcptssequence"`
	Times         Times         `json:"times"           xml:"times"`
	Trace         Trace         `json:"trace"           xml:"trace"`
	Uptime        Uptime        `json:"uptime"          xml:"uptime"`
	Comment       string        `json:"comment"         xml:"comment,attr"`
	Addresses     []Address     `json:"addresses"       xml:"address"`
	ExtraPorts    []ExtraPort   `json:"extra_ports"     xml:"ports>extraports"`
	Hostnames     []Hostname    `json:"hostnames"       xml:"hostnames>hostname"`
	HostScripts   []Script      `json:"host_scripts"    xml:"hostscript>script"`
	Ports         []Port        `json:"ports"           xml:"ports>port"`
	Smurfs        []Smurf       `json:"smurfs"          xml:"smurf"`
}

// Status represents a host's status.
type Status struct {
	State     string  `json:"state"      xml:"state,attr"`
	Reason    string  `json:"reason"     xml:"reason,attr"`
	ReasonTTL float32 `json:"reason_ttl" xml:"reason_ttl,attr"`
}

func (s Status) String() string {
	return s.State
}

// Address contains a IPv4 or IPv6 address for a host.
type Address struct {
	Addr     string `json:"addr"      xml:"addr,attr"`
	AddrType string `json:"addr_type" xml:"addrtype,attr"`
	Vendor   string `json:"vendor"    xml:"vendor,attr"`
}

func (a Address) String() string {
	return a.Addr
}

// Hostname is a name for a host.
type Hostname struct {
	Name string `json:"name" xml:"name,attr"`
	Type string `json:"type" xml:"type,attr"`
}

func (h Hostname) String() string {
	return h.Name
}

// Smurf contains responses from a smurf attack.
type Smurf struct {
	Responses string `json:"responses" xml:"responses,attr"`
}

// ExtraPort contains the information about the closed and filtered ports.
type ExtraPort struct {
	State   string   `json:"state"   xml:"state,attr"`
	Count   int      `json:"count"   xml:"count,attr"`
	Reasons []Reason `json:"reasons" xml:"extrareasons"`
}

// Reason represents a reason why a port is closed or filtered.
// This won't be in the scan results unless WithReason is used.
type Reason struct {
	Reason string `json:"reason" xml:"reason,attr"`
	Count  int    `json:"count"  xml:"count,attr"`
}

// Port contains all the information about a scanned port.
type Port struct {
	ID       uint16   `json:"id"       xml:"portid,attr"`
	Protocol string   `json:"protocol" xml:"protocol,attr"`
	Owner    Owner    `json:"owner"    xml:"owner"`
	Service  Service  `json:"service"  xml:"service"`
	State    State    `json:"state"    xml:"state"`
	Scripts  []Script `json:"scripts"  xml:"script"`
}

// PortStatus represents a port's state.
type PortStatus string

// Enumerates the different possible state values.
const (
	Open       PortStatus = "open"
	Closed     PortStatus = "closed"
	Filtered   PortStatus = "filtered"
	Unfiltered PortStatus = "unfiltered"
)

// Status returns the status of a port.
func (p Port) Status() PortStatus {
	return PortStatus(p.State.State)
}

// State contains information about a given port's status.
// State is open, closed, etc.
type State struct {
	State     string  `json:"state"      xml:"state,attr"`
	Reason    string  `json:"reason"     xml:"reason,attr"`
	ReasonIP  string  `json:"reason_ip"  xml:"reason_ip,attr"`
	ReasonTTL float32 `json:"reason_ttl" xml:"reason_ttl,attr"`
}

func (s State) String() string {
	return s.State
}

// Owner contains the name of a port's owner.
type Owner struct {
	Name string `json:"name" xml:"name,attr"`
}

func (o Owner) String() string {
	return o.Name
}

// Service contains detailed information about a service on an open port.
type Service struct {
	DeviceType  string `json:"device_type"  xml:"devicetype,attr"`
	ExtraInfo   string `json:"extra_info"   xml:"extrainfo,attr"`
	HighVersion string `json:"high_version" xml:"highver,attr"`
	Hostname    string `json:"hostname"     xml:"hostname,attr"`
	LowVersion  string `json:"low_version"  xml:"lowver,attr"`
	Method      string `json:"method"       xml:"method,attr"`
	Name        string `json:"name"         xml:"name,attr"`
	OSType      string `json:"os_type"      xml:"ostype,attr"`
	Product     string `json:"product"      xml:"product,attr"`
	Proto       string `json:"proto"        xml:"proto,attr"`
	RPCNum      string `json:"rpc_num"      xml:"rpcnum,attr"`
	ServiceFP   string `json:"service_fp"   xml:"servicefp,attr"`
	Tunnel      string `json:"tunnel"       xml:"tunnel,attr"`
	Version     string `json:"version"      xml:"version,attr"`
	Confidence  int    `json:"confidence"   xml:"conf,attr"`
	CPEs        []CPE  `json:"cpes"         xml:"cpe"`
}

func (s Service) String() string {
	return s.Name
}

// CPE (Common Platform Enumeration) is a standardized way to name software
// applications, operating systems and hardware platforms.
type CPE string

// Script represents an Nmap Scripting Engine script.
// The inner elements can be an arbitrary collection of Tables and Elements. Both of them can also be empty.
type Script struct {
	ID       string    `json:"id"                 xml:"id,attr"`
	Output   string    `json:"output"             xml:"output,attr"`
	Elements []Element `json:"elements,omitempty" xml:"elem,omitempty"`
	Tables   []Table   `json:"tables,omitempty"   xml:"table,omitempty"`
}

// Table is an arbitrary collection of (sub-)Tables and Elements. All its fields can be empty.
type Table struct {
	Key      string    `json:"key,omitempty"      xml:"key,attr,omitempty"`
	Tables   []Table   `json:"tables,omitempty"   xml:"table,omitempty"`
	Elements []Element `json:"elements,omitempty" xml:"elem,omitempty"`
}

// Element is the smallest building block for scripts/tables. It can optionally(!) have a key.
type Element struct {
	Key   string `json:"key,omitempty" xml:"key,attr,omitempty"`
	Value string `json:"value"         xml:",innerxml"`
}

// OS contains the fingerprinted operating system for a host.
type OS struct {
	PortsUsed    []PortUsed      `json:"ports_used"      xml:"portused"`
	Matches      []OSMatch       `json:"os_matches"      xml:"osmatch"`
	Fingerprints []OSFingerprint `json:"os_fingerprints" xml:"osfingerprint"`
}

// PortUsed is the port used to fingerprint an operating system.
type PortUsed struct {
	State string `json:"state"   xml:"state,attr"`
	Proto string `json:"proto"   xml:"proto,attr"`
	ID    int    `json:"port_id" xml:"portid,attr"`
}

// OSMatch contains detailed information regarding an operating system fingerprint.
type OSMatch struct {
	Name     string    `json:"name"       xml:"name,attr"`
	Accuracy int       `json:"accuracy"   xml:"accuracy,attr"`
	Line     int       `json:"line"       xml:"line,attr"`
	Classes  []OSClass `json:"os_classes" xml:"osclass"`
}

// OSClass contains vendor information about an operating system.
type OSClass struct {
	Vendor       string `json:"vendor"        xml:"vendor,attr"`
	OSGeneration string `json:"os_generation" xml:"osgen,attr"`
	Type         string `json:"type"          xml:"type,attr"`
	Accuracy     int    `json:"accuracy"      xml:"accuracy,attr"`
	Family       string `json:"os_family"     xml:"osfamily,attr"`
	CPEs         []CPE  `json:"cpes"          xml:"cpe"`
}

// OSFamily returns the OS family in an enumerated format.
func (o OSClass) OSFamily() family.OSFamily {
	return family.OSFamily(o.Family)
}

// OSFingerprint is the actual fingerprint string of an operating system.
type OSFingerprint struct {
	Fingerprint string `json:"fingerprint" xml:"fingerprint,attr"`
}

// Distance is the amount of hops to a particular host.
type Distance struct {
	Value int `json:"value" xml:"value,attr"`
}

// Uptime is the amount of time the host has been up.
type Uptime struct {
	Seconds  int    `json:"seconds"   xml:"seconds,attr"`
	Lastboot string `json:"last_boot" xml:"lastboot,attr"`
}

// Sequence represents a detected sequence.
type Sequence struct {
	Class  string `json:"class"  xml:"class,attr"`
	Values string `json:"values" xml:"values,attr"`
}

// TCPSequence represents a detected TCP sequence.
type TCPSequence struct {
	Index      int    `json:"index"      xml:"index,attr"`
	Difficulty string `json:"difficulty" xml:"difficulty,attr"`
	Values     string `json:"values"     xml:"values,attr"`
}

// IPIDSequence represents a detected IP ID sequence.
type IPIDSequence Sequence

// TCPTSSequence represents a detected TCP TS sequence.
type TCPTSSequence Sequence

// Trace represents the trace to a host, including the hops.
type Trace struct {
	Proto string `json:"proto" xml:"proto,attr"`
	Port  int    `json:"port"  xml:"port,attr"`
	Hops  []Hop  `json:"hops"  xml:"hop"`
}

// Hop is an IP hop to a host.
type Hop struct {
	TTL    float32 `json:"ttl"     xml:"ttl,attr"`
	RTT    string  `json:"rtt"     xml:"rtt,attr"`
	IPAddr string  `json:"ip_addr" xml:"ipaddr,attr"`
	Host   string  `json:"host"    xml:"host,attr"`
}

// Times contains time statistics for an nmap scan.
type Times struct {
	SRTT string `json:"srtt" xml:"srtt,attr"`
	RTT  string `json:"rttv" xml:"rttvar,attr"`
	To   string `json:"to"   xml:"to,attr"`
}

// Stats contains statistics for an nmap scan.
type Stats struct {
	Finished Finished  `json:"finished" xml:"finished"`
	Hosts    HostStats `json:"hosts"    xml:"hosts"`
}

// Finished contains detailed statistics regarding a finished scan.
type Finished struct {
	Time     Timestamp `json:"time"      xml:"time,attr"`
	TimeStr  string    `json:"time_str"  xml:"timestr,attr"`
	Elapsed  float32   `json:"elapsed"   xml:"elapsed,attr"`
	Summary  string    `json:"summary"   xml:"summary,attr"`
	Exit     string    `json:"exit"      xml:"exit,attr"`
	ErrorMsg string    `json:"error_msg" xml:"errormsg,attr"`
}

// HostStats contains the amount of up and down hosts and the total count.
type HostStats struct {
	Up    int `json:"up"    xml:"up,attr"`
	Down  int `json:"down"  xml:"down,attr"`
	Total int `json:"total" xml:"total,attr"`
}

// Timestamp represents time as a UNIX timestamp in seconds.
type Timestamp time.Time

// ParseTime converts a UNIX timestamp string to a time.Time.
func (t *Timestamp) ParseTime(s string) error {
	timestamp, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return err
	}

	*t = Timestamp(time.Unix(timestamp, 0))

	return nil
}

// FormatTime formats the time.Time value as a UNIX timestamp string.
func (t *Timestamp) FormatTime() string {
	return strconv.FormatInt(time.Time(*t).Unix(), 10)
}

// MarshalJSON implements the json.Marshaler interface.
func (t *Timestamp) MarshalJSON() ([]byte, error) {
	return []byte(t.FormatTime()), nil
}

// UnmarshalJSON implements the json.Unmarshaler interface.
func (t *Timestamp) UnmarshalJSON(b []byte) error {
	return t.ParseTime(string(b))
}

// MarshalXMLAttr implements the xml.MarshalerAttr interface.
func (t *Timestamp) MarshalXMLAttr(name xml.Name) (xml.Attr, error) {
	if time.Time(*t).IsZero() {
		return xml.Attr{}, nil
	}

	return xml.Attr{Name: name, Value: t.FormatTime()}, nil
}

// UnmarshalXMLAttr implements the xml.UnmarshalXMLAttr interface.
func (t *Timestamp) UnmarshalXMLAttr(attr xml.Attr) (err error) {
	return t.ParseTime(attr.Value)
}

// parse takes a byte array of nmap xml data and unmarshal it into a Run struct.
func parse(content []byte) (*Run, error) {
	result := Run{
		rawXML: append([]byte(nil), content...),
	}

	err := xml.Unmarshal(content, &result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}
