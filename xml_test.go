package nmap

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	family "github.com/Ullaakut/nmap/v4/pkg/osfamilies"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseTime(t *testing.T) {
	ts := Timestamp{}

	err := ts.ParseTime("invalid")
	assert.Error(t, err)
}

func TestFormatTime(t *testing.T) {
	originalStr := "123456789"
	ts := Timestamp{}

	err := ts.ParseTime(originalStr)
	require.NoError(t, err)

	result := ts.FormatTime()
	assert.Equal(t, originalStr, result)
}

func TestOSFamily(t *testing.T) {
	osc := OSClass{
		Family: "Linux",
	}

	assert.Equal(t, family.Linux, osc.OSFamily())
}

func TestParseTableXML(t *testing.T) {
	expectedTable := Table{
		Key: "key123",
		Elements: []Element{
			{
				Key:   "key",
				Value: "AAAAB3NzaC1yc2EAAAABIwAAAQEAwVKoTY/7GFG7BmKkG6qFAHY/f3ciDX2MXTBLMEJP0xyUJsoy/CVRYw2b4qUB/GCJ5lh2InP+LVnPD3ZdtpyIvbS0eRZs/BH+mVLGh9xA/wOEUiiCfzQRsHj1xn7cqeWViAzQtdGluk/5CVAvr1FU3HNaaWkg7KQOSiKAzgDwCBtQhlgI40xdXgbqMkrHeP4M1p4MxoEVpZMe4oObACWwazeHP/Xas1vy5rbnmE59MpEZaA8t7AfGlW4MrVMhAB1JsFMdd0qFLpy/l93H3ptSlx1+6PQ5gUyjhmDUjMR+k6fb0yOeGdOrjN8IrWPmebZRFBjK5aCJwubgY/03VsSBMQ==",
			},
			{
				Key:   "fingerprint",
				Value: "79f809acd4e232421049d3bd208285ec",
			},
			{
				Key:   "type",
				Value: "ssh-rsa",
			},
			{
				Key:   "bits",
				Value: "2048",
			},
			{
				Value: "just some value",
			},
		},
		Tables: []Table{
			{
				Elements: []Element{
					{
						Key:   "important element",
						Value: "ssh-rsa",
					},
					{
						Value: "just some value",
					},
				},
			},
			{
				Key: "dialects",
				Elements: []Element{
					{
						Value: "2.02",
					},
					{
						Value: "2.10",
					},
				},
			},
		},
	}

	input := []byte(fmt.Sprintf(
		`<table key="%s">
					<elem key="%s">%s</elem>
					<elem key="%s">%s</elem>
					<elem key="%s">%s</elem>
					<elem key="%s">%s</elem>
					<elem key="%s">%s</elem>
					<table key = %s"">
						<elem key="%s">%s</elem>
						<elem key="%s">%s</elem>
					</table>
					<table key = "%s">
						<elem key="%s">%s</elem>
						<elem key="%s">%s</elem>
					</table>
				</table>`,
		expectedTable.Key,
		expectedTable.Elements[0].Key, expectedTable.Elements[0].Value,
		expectedTable.Elements[1].Key, expectedTable.Elements[1].Value,
		expectedTable.Elements[2].Key, expectedTable.Elements[2].Value,
		expectedTable.Elements[3].Key, expectedTable.Elements[3].Value,
		expectedTable.Elements[4].Key, expectedTable.Elements[4].Value,
		expectedTable.Tables[0].Key,
		expectedTable.Tables[0].Elements[0].Key, expectedTable.Tables[0].Elements[0].Value,
		expectedTable.Tables[0].Elements[1].Key, expectedTable.Tables[0].Elements[1].Value,
		expectedTable.Tables[1].Key,
		expectedTable.Tables[1].Elements[0].Key, expectedTable.Tables[1].Elements[0].Value,
		expectedTable.Tables[1].Elements[1].Key, expectedTable.Tables[1].Elements[1].Value,
	))

	var table Table
	err := xml.Unmarshal(input, &table)
	require.NoError(t, err)

	// Outermost table.
	assert.Equal(t, expectedTable.Key, table.Key)
	assert.Len(t, table.Elements, len(expectedTable.Elements))
	for idx := range table.Elements {
		assert.Equal(t, expectedTable.Elements[idx].Key, table.Elements[idx].Key)
	}

	// Nested tables
	assert.Len(t, table.Tables, len(expectedTable.Tables))
	for idx := range table.Tables {
		assert.Equal(t, expectedTable.Tables[idx].Key, table.Tables[idx].Key)
		assert.ElementsMatch(t, expectedTable.Tables[idx].Elements, table.Tables[idx].Elements)
	}
}

func TestFormatTableXML(t *testing.T) {
	table := Table{
		Key: "key123",
		Elements: []Element{
			{Key: "key", Value: "AAAAB3NzaC1yc2EAAAABIwAAAQEAwVKoTY/7GFG7BmKkG6qFAHY/f3ciDX2MXTBLMEJP0xyUJsoy/CVRYw2b4qUB/GCJ5lh2InP+LVnPD3ZdtpyIvbS0eRZs/BH+mVLGh9xA/wOEUiiCfzQRsHj1xn7cqeWViAzQtdGluk/5CVAvr1FU3HNaaWkg7KQOSiKAzgDwCBtQhlgI40xdXgbqMkrHeP4M1p4MxoEVpZMe4oObACWwazeHP/Xas1vy5rbnmE59MpEZaA8t7AfGlW4MrVMhAB1JsFMdd0qFLpy/l93H3ptSlx1+6PQ5gUyjhmDUjMR+k6fb0yOeGdOrjN8IrWPmebZRFBjK5aCJwubgY/03VsSBMQ=="},
			{Key: "fingerprint", Value: "79f809acd4e232421049d3bd208285ec"},
			{Key: "type", Value: "ssh-rsa"},
			{Key: "bits", Value: "2048"},
			{Value: "just some value"},
		},
		Tables: []Table{
			{
				Elements: []Element{
					{Key: "important element", Value: "ssh-rsa"},
					{Value: "just some value"},
				},
			},
			{
				Key: "dialects",
				Elements: []Element{
					{Value: "2.02"},
					{Value: "2.10"},
				},
			},
		},
	}

	expectedXML := [][]byte{
		[]byte(fmt.Sprintf(`<Table key="%s">`, table.Key)),
		[]byte(fmt.Sprintf(`<table>`)),
		[]byte(fmt.Sprintf(`<elem key="%s">%s</elem>`, table.Tables[0].Elements[0].Key, table.Tables[0].Elements[0].Value)),
		[]byte(fmt.Sprintf(`<elem>%s</elem>`, table.Tables[0].Elements[1].Value)),
		[]byte(fmt.Sprintf(`</table>`)),
		[]byte(fmt.Sprintf(`<table key="%s">`, table.Tables[1].Key)),
		[]byte(fmt.Sprintf(`<elem>%s</elem>`, table.Tables[1].Elements[0].Value)),
		[]byte(fmt.Sprintf(`<elem>%s</elem>`, table.Tables[1].Elements[1].Value)),
		[]byte(fmt.Sprintf(`</table>`)),
		[]byte(fmt.Sprintf(`<elem key="%s">%s</elem>`, table.Elements[0].Key, table.Elements[0].Value)),
		[]byte(fmt.Sprintf(`<elem key="%s">%s</elem>`, table.Elements[1].Key, table.Elements[1].Value)),
		[]byte(fmt.Sprintf(`<elem key="%s">%s</elem>`, table.Elements[2].Key, table.Elements[2].Value)),
		[]byte(fmt.Sprintf(`<elem key="%s">%s</elem>`, table.Elements[3].Key, table.Elements[3].Value)),
		[]byte(fmt.Sprintf(`<elem>%s</elem>`, table.Elements[4].Value)),
		[]byte(fmt.Sprintf(`</Table>`)),
	}

	XML, err := xml.Marshal(table)
	require.NoError(t, err)

	for _, expectedXMLElement := range expectedXML {
		assert.Contains(t, string(XML), string(expectedXMLElement))
	}
}

func TestStringMethods(t *testing.T) {
	s := Status{
		State: "up",
	}
	assert.Equal(t, s.State, s.String())

	a := Address{
		Addr: "192.168.1.1",
	}
	assert.Equal(t, a.Addr, a.String())

	h := Hostname{
		Name: "toto.test",
	}
	assert.Equal(t, h.Name, h.String())

	s2 := State{
		State: "open",
	}
	assert.Equal(t, s2.State, s2.String())

	o := Owner{
		Name: "test",
	}
	assert.Equal(t, o.Name, o.String())

	s3 := Service{
		Name: "http",
	}
	assert.Equal(t, s3.Name, s3.String())
}

func TestToFile(t *testing.T) {
	r := &Run{}

	err := r.ToFile(os.TempDir() + string(os.PathSeparator) + "toto.txt")
	require.NoError(t, err)
}

func TestToReader(t *testing.T) {
	inputFile := "tests/xml/scan_base.xml"
	rawXML, err := os.ReadFile(inputFile)
	require.NoError(t, err)

	result, err := parse(rawXML)
	require.NoError(t, err)

	reader := result.ToReader()
	byteOutput, err := io.ReadAll(reader)
	require.NoError(t, err)

	assert.Equal(t, string(byteOutput), string(rawXML))
}

func TestTimestampJSONMarshaling(t *testing.T) {
	dateTime := time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC)
	dateBytes := []byte("943920000")

	ts := Timestamp(dateTime)
	ts2 := Timestamp{}

	b, err := ts.MarshalJSON()
	require.NoError(t, err)
	assert.Equal(t, []byte("943920000"), b)

	err = json.Unmarshal(dateBytes, &ts2)
	require.NoError(t, err)

	assert.Equal(t, ts.FormatTime(), ts2.FormatTime())
}

func TestTimestampXMLMarshaling(t *testing.T) {
	attrName := xml.Name{Local: "ts"}
	dateTime := time.Date(2000, 0, 0, 0, 0, 0, 0, time.UTC)
	dateXML := xml.Attr{Name: attrName, Value: "943920000"}

	ts := Timestamp(dateTime)
	ts2 := Timestamp{}

	got, err := ts.MarshalXMLAttr(attrName)
	require.NoError(t, err)
	assert.Equal(t, dateXML.Value, got.Value)

	got, err = ts2.MarshalXMLAttr(attrName)
	require.NoError(t, err)
	assert.Equal(t, xml.Attr{}, got)

	err = ts2.UnmarshalXMLAttr(dateXML)
	require.NoError(t, err)
	assert.Equal(t, ts.FormatTime(), ts2.FormatTime())
}

func TestParseRunXML(t *testing.T) {
	tests := []struct {
		inputFile string

		expectedResult *Run
		wantErr        require.ErrorAssertionFunc
	}{
		{
			inputFile: "tests/xml/scan_base.xml",

			expectedResult: &Run{
				Args:             "nmap -A -v -oX sample-03.xml freshmeat.net sourceforge.net nmap.org kernel.org openbsd.org netbsd.org google.com gmail.com",
				Scanner:          "nmap",
				StartStr:         "Sun Jan 27 21:10:02 2008",
				Version:          "4.53",
				XMLOutputVersion: "1.01",
				ScanInfo: ScanInfo{
					NumServices: 1714,
					Protocol:    "tcp",
					Services:    "1-1027,1029-1033,1040,1043,1050,1058-1059,1067-1068,1076,1080,1083-1084,1103,1109-1110,1112,1127,1139,1155,1158,1178,1212,1214,1220,1222,1234,1241,1248,1270,1337,1346-1381,1383-1552,1600,1650-1652,1661-1672,1680,1720,1723,1755,1761-1764,1827,1900,1935,1984,1986-2028,2030,2032-2035,2038,2040-2049,2053,2064-2065,2067-2068,2105-2106,2108,2111-2112,2120-2121,2201,2232,2241,2301,2307,2401,2430-2433,2500-2501,2564,2600-2605,2627-2628,2638,2766,2784,2809,2903,2998,3000-3001,3005-3006,3025,3045,3049,3052,3064,3086,3128,3141,3264,3268-3269,3292,3299,3306,3333,3372,3389,3397-3399,3421,3455-3457,3462,3531,3632,3689,3900,3984-3986,3999-4000,4002,4008,4045,4125,4132-4133,4144,4199,4224,4321,4333,4343,4444,4480,4500,4557,4559,4660,4662,4672,4899,4987,4998,5000-5003,5009-5011,5050,5060,5100-5102,5145,5190-5193,5232,5236,5300-5305,5308,5400,5405,5432,5490,5500,5510,5520,5530,5540,5550,5555,5560,5631-5632,5679-5680,5713-5717,5800-5803,5900-5903,5977-5979,5997-6009,6017,6050,6101,6103,6105-6106,6110-6112,6141-6148,6222,6346-6347,6400-6401,6502,6543-6544,6547-6548,6558,6588,6662,6665-6670,6699-6701,6881,6969,7000-7010,7070,7100,7200-7201,7273,7326,7464,7597,7937-7938,8000,8007,8009,8021,8076,8080-8082,8118,8123,8443,8770,8888,8892,9040,9050-9051,9090,9100-9107,9111,9152,9535,9876,9991-9992,9999-10000,10005,10082-10083,11371,12000,12345-12346,13701-13702,13705-13706,13708-13718,13720-13722,13782-13783,14141,15126,15151,16080,16444,16959,17007,17300,18000,18181-18185,18187,19150,20005,22273,22289,22305,22321,22370,26208,27000-27010,27374,27665,31337,31416,32770-32780,32786-32787,38037,38292,43188,44334,44442-44443,47557,49400,50000,50002,54320,61439-61441,65301",
					Type:        "syn",
				},
				Start: Timestamp(time.Unix(1201479002, 0)),
				Verbose: Verbose{
					Level: 1,
				},
				Stats: Stats{
					Finished: Finished{
						Time:    Timestamp(time.Unix(1201481569, 0)),
						TimeStr: "Sun Jan 27 21:52:49 2008",
					},
					Hosts: HostStats{
						Up:    8,
						Total: 8,
						Down:  0,
					},
				},
				Hosts: []Host{
					{
						StartTime: Timestamp(time.Unix(1684341000, 0)),
						EndTime:   Timestamp(time.Unix(1684342000, 0)),
						TimedOut:  true,
						IPIDSequence: IPIDSequence{
							Class:  "All zeros",
							Values: "0,0,0,0,0,0",
						},
						OS: OS{
							PortsUsed: []PortUsed{
								{
									State: "open",
									Proto: "tcp",
									ID:    80,
								},
								{
									State: "closed",
									Proto: "tcp",
									ID:    443,
								},
							},
							Matches: []OSMatch{
								{
									Name:     "MicroTik RouterOS 2.9.46",
									Accuracy: 94,
									Line:     14788,
									Classes: []OSClass{
										{
											Vendor:       "MikroTik",
											OSGeneration: "2.X",
											Type:         "software router",
											Accuracy:     94,
											Family:       "RouterOS",
										},
									},
								},
								{
									Name:     "Linksys WRT54GS WAP (Linux kernel)",
									Accuracy: 94,
									Line:     8292,
									Classes: []OSClass{
										{
											Vendor:       "Linksys",
											OSGeneration: "2.4.X",
											Type:         "WAP",
											Accuracy:     94,
											Family:       "Linux",
										},
									},
								},
								{
									Name:     "Linux 2.4.18 - 2.4.32 (likely embedded)",
									Accuracy: 94,
									Line:     8499,
									Classes: []OSClass{
										{
											Vendor:   "WebVOIZE",
											Type:     "VoIP phone",
											Accuracy: 94,
											Family:   "embedded",
										},
										{
											Vendor:   "Inventel",
											Type:     "WAP",
											Accuracy: 91,
											Family:   "embedded",
										},
										{
											Vendor:   "USRobotics",
											Type:     "broadband router",
											Accuracy: 91,
											Family:   "embedded",
										},
										{
											Vendor:   "Netgear",
											Type:     "WAP",
											Accuracy: 91,
											Family:   "embedded",
										},
										{
											Vendor:   "QLogic",
											Type:     "switch",
											Accuracy: 91,
											Family:   "embedded",
										},
										{
											Vendor:       "Linux",
											OSGeneration: "2.4.X",
											Type:         "broadband router",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:   "Xerox",
											Type:     "printer",
											Accuracy: 90,
											Family:   "embedded",
										},
										{
											Vendor:   "Roku",
											Type:     "media device",
											Accuracy: 89,
											Family:   "embedded",
										},
									},
								},
								{
									Name:     "Linux 2.4.21 - 2.4.33",
									Accuracy: 94,
									Line:     8624,
									Classes: []OSClass{
										{
											Vendor:       "Linux",
											OSGeneration: "2.4.X",
											Type:         "general purpose",
											Accuracy:     94,
											Family:       "Linux",
										},
										{
											Vendor:       "D-Link",
											OSGeneration: "2.4.X",
											Type:         "WAP",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:       "Linux",
											OSGeneration: "2.4.X",
											Type:         "WAP",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:       "3Com",
											OSGeneration: "2.4.X",
											Type:         "broadband router",
											Accuracy:     89,
											Family:       "Linux",
										},
									},
								},
								{
									Name:     "Linux 2.4.27",
									Accuracy: 94,
									Line:     8675,
									Classes: []OSClass{
										{
											Vendor:       "Sharp",
											OSGeneration: "2.4.X",
											Type:         "PDA",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:       "Linux",
											OSGeneration: "2.4.X",
											Type:         "media device",
											Accuracy:     91,
											Family:       "Linux",
										},
									},
								},
								{
									Name:     "Linux 2.4.28 - 2.4.30",
									Accuracy: 94,
									Line:     8693,
								},
								{
									Name:     "Linux 2.6.5 - 2.6.18",
									Accuracy: 94,
									Line:     11411,
									Classes: []OSClass{
										{
											Vendor:       "Linux",
											OSGeneration: "2.6.X",
											Type:         "general purpose",
											Accuracy:     94,
											Family:       "Linux",
										},
									},
								},
								{
									Name:     "Linux 2.6.8",
									Accuracy: 94,
									Line:     11485,
									Classes: []OSClass{
										{
											Vendor:       "Dream Multimedia",
											OSGeneration: "2.6.X",
											Type:         "media device",
											Accuracy:     89,
											Family:       "Linux",
										},
										{
											Vendor:       "Iomega",
											OSGeneration: "2.6.X",
											Type:         "storage-misc",
											Accuracy:     89,
											Family:       "Linux",
										},
									},
								},
								{
									Name:     "WebVOIZE 120 IP phone",
									Accuracy: 94,
									Line:     18921,
									Classes: []OSClass{
										{
											Vendor:       "FON",
											OSGeneration: "2.6.X",
											Type:         "WAP",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:       "Linux",
											OSGeneration: "2.4.X",
											Type:         "VoIP gateway",
											Accuracy:     91,
											Family:       "Linux",
										},
										{
											Vendor:       "FON",
											OSGeneration: "2.4.X",
											Type:         "WAP",
											Accuracy:     90,
											Family:       "Linux",
										},
										{
											Vendor:   "Belkin",
											Type:     "WAP",
											Accuracy: 90,
											Family:   "embedded",
										},
										{
											Vendor:   "Asus",
											Type:     "WAP",
											Accuracy: 90,
											Family:   "embedded",
										},
										{
											Vendor:       "Netgear",
											OSGeneration: "2.4.X",
											Type:         "WAP",
											Accuracy:     90,
											Family:       "Linux",
										},
										{
											Vendor:   "Occam",
											Type:     "VoIP gateway",
											Accuracy: 89,
											Family:   "embedded",
										},
										{
											Vendor:   "Siemens",
											Type:     "WAP",
											Accuracy: 89,
											Family:   "Linux",
										},
									},
								},
								{
									Name:     "Linux 2.4.2 (Red Hat 7.1)",
									Accuracy: 91,
									Line:     8533,
									Classes: []OSClass{
										{
											Vendor:       "Aladdin",
											OSGeneration: "2.4.X",
											Type:         "security-misc",
											Accuracy:     89,
											Family:       "Linux",
										},
									},
								},
							},
							Fingerprints: []OSFingerprint{
								{
									Fingerprint: fingerprint,
								},
							},
						},
						Status: Status{
							State:  "up",
							Reason: "reset",
						},
						TCPSequence: TCPSequence{
							Index:      242,
							Difficulty: "Good luck!",
							Values:     "457B276,4584FC8,161C122C,161B185F,1605EA95,1614C498",
						},
						TCPTSSequence: TCPTSSequence{
							Class:  "other",
							Values: "3FB03AA9,3FB03C75,45B26360,45B2636A,45B26374,45B2637E",
						},
						Times: Times{
							SRTT: "269788",
							RTT:  "41141",
							To:   "434352",
						},
						Trace: Trace{
							Proto: "tcp",
							Port:  80,
							Hops: []Hop{
								{
									TTL:    1,
									RTT:    "1.83",
									IPAddr: "192.168.254.254",
								},
								{
									TTL:    2,
									RTT:    "18.95",
									IPAddr: "200.217.89.32",
								},
								{
									TTL:    3,
									RTT:    "18.33",
									IPAddr: "200.217.30.250",
									Host:   "gigabitethernet5-1.80-cto-rn-rotd-02.telemar.net.br",
								},
								{
									TTL:    4,
									RTT:    "45.05",
									IPAddr: "200.97.65.250",
									Host:   "pos15-1-nbv-pe-rotd-03.telemar.net.br",
								},
								{
									TTL:    5,
									RTT:    "43.49",
									IPAddr: "200.223.131.13",
									Host:   "pos6-0-nbv-pe-rotn-01.telemar.net.br",
								},
								{
									TTL:    6,
									RTT:    "91.27",
									IPAddr: "200.223.131.205",
									Host:   "so-0-2-0-0-arc-rj-rotn-01.telemar.net.br",
								},
								{
									TTL:    8,
									RTT:    "191.87",
									IPAddr: "200.223.131.110",
									Host:   "PO0-3.ARC-RJ-ROTN-01.telemar.net.br",
								},
								{
									TTL:    9,
									RTT:    "177.30",
									IPAddr: "208.173.90.89",
									Host:   "bpr2-so-5-2-0.miamimit.savvis.net",
								},
								{
									TTL:    10,
									RTT:    "181.50",
									IPAddr: "208.172.97.169",
									Host:   "cr2-pos-0-3-1-0.miami.savvis.net",
								},
								{
									TTL:    11,
									RTT:    "336.43",
									IPAddr: "206.24.210.70",
									Host:   "cr1-loopback.sfo.savvis.net",
								},
								{
									TTL:    12,
									RTT:    "245.32",
									IPAddr: "204.70.200.229",
									Host:   "er1-te-1-0-1.SanJose3Equinix.savvis.net",
								},
								{
									TTL:    13,
									RTT:    "238.47",
									IPAddr: "204.70.200.210",
									Host:   "hr1-te-2-0-0.santaclarasc4.savvis.net",
								},
								{
									TTL:    14,
									RTT:    "322.90",
									IPAddr: "204.70.200.217",
									Host:   "hr1-te-2-0-0.santaclarasc9.savvis.net",
								},
								{
									TTL:    15,
									RTT:    "330.96",
									IPAddr: "204.70.203.146",
								},
								{
									TTL:    16,
									RTT:    "342.57",
									IPAddr: "66.35.194.59",
									Host:   "csr2-ve242.santaclarasc8.savvis.net",
								},
								{
									TTL:    17,
									RTT:    "248.22",
									IPAddr: "66.35.210.202",
								},
								{
									TTL:    18,
									RTT:    "238.36",
									IPAddr: "66.35.250.168",
									Host:   "freshmeat.net",
								},
							},
						},
						Uptime: Uptime{
							Seconds:  206,
							Lastboot: "Sun Jan 27 21:43:11 2008",
						},
						Addresses: []Address{
							{
								Addr:     "66.35.250.168",
								AddrType: "ipv4",
							},
						},
						ExtraPorts: []ExtraPort{
							{
								State: "filtered",
								Count: 1712,
								Reasons: []Reason{
									{
										Reason: "host-prohibiteds",
										Count:  1712,
									},
								},
							},
						},
						Hostnames: []Hostname{
							{
								Name: "freshmeat.net",
								Type: "PTR",
							},
						},
						Ports: []Port{
							{
								ID:       80,
								Protocol: "tcp",
								Service: Service{
									Name:       "http",
									ExtraInfo:  "(Unix) PHP/4.4.7",
									Method:     "probed",
									Product:    "Apache httpd",
									Version:    "1.3.39",
									Confidence: 10,
								},
								State: State{
									State:     "open",
									Reason:    "syn-ack",
									ReasonTTL: 45,
								},
								Scripts: []Script{
									{
										ID:     "robots.txt",
										Output: "User-Agent: * /img/ /redir/ ",
									},
									{
										ID:     "HTML title",
										Output: "freshmeat.net: Welcome to freshmeat.net",
									},
								},
							},
							{
								ID:       443,
								Protocol: "tcp",
								Service: Service{
									Name:       "https",
									Method:     "table",
									Confidence: 3,
								},
								State: State{
									State:     "closed",
									Reason:    "reset",
									ReasonTTL: 46,
								},
							},
						},
					},
				},
				TaskBegin: []Task{
					{
						Time: Timestamp(time.Unix(1201479013, 0)),
						Task: "Ping Scan",
					},
					{
						Time: Timestamp(time.Unix(1201479014, 0)),
						Task: "Parallel DNS resolution of 8 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201479015, 0)),
						Task: "System CNAME DNS resolution of 4 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201479016, 0)),
						Task: "SYN Stealth Scan",
					},
					{
						Time: Timestamp(time.Unix(1201480879, 0)),
						Task: "Service scan",
					},
					{
						Time: Timestamp(time.Unix(1201481006, 0)),
						Task: "Traceroute",
					},
					{
						Time: Timestamp(time.Unix(1201481028, 0)),
						Task: "Traceroute",
					},
					{
						Time: Timestamp(time.Unix(1201481059, 0)),
						Task: "Parallel DNS resolution of 85 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201481070, 0)),
						Task: "System CNAME DNS resolution of 8 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201481086, 0)),
						Task: "SCRIPT ENGINE",
					},
				},
				TaskProgress: []TaskProgress{
					{
						Percent:   3.22,
						Remaining: 903,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201479949, 0)),
						Time:      Timestamp(time.Unix(1201479046, 0)),
					},
					{
						Percent:   56.66,
						Remaining: 325,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201479767, 0)),
						Time:      Timestamp(time.Unix(1201479442, 0)),
					},
					{
						Percent:   77.02,
						Remaining: 225,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201479995, 0)),
						Time:      Timestamp(time.Unix(1201479770, 0)),
					},
					{
						Percent:   81.95,
						Remaining: 215,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480212, 0)),
						Time:      Timestamp(time.Unix(1201479996, 0)),
					},
					{
						Percent:   86.79,
						Remaining: 182,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480395, 0)),
						Time:      Timestamp(time.Unix(1201480213, 0)),
					},
					{
						Percent:   87.84,
						Remaining: 172,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480433, 0)),
						Time:      Timestamp(time.Unix(1201480260, 0)),
					},
					{
						Percent:   91.65,
						Remaining: 129,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480564, 0)),
						Time:      Timestamp(time.Unix(1201480435, 0)),
					},
					{
						Percent:   94.43,
						Remaining: 91,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480656, 0)),
						Time:      Timestamp(time.Unix(1201480565, 0)),
					},
					{
						Percent:   96.35,
						Remaining: 62,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480720, 0)),
						Time:      Timestamp(time.Unix(1201480658, 0)),
					},
					{
						Percent:   97.76,
						Remaining: 39,
						Task:      "SYN Stealth Scan",
						Etc:       Timestamp(time.Unix(1201480760, 0)),
						Time:      Timestamp(time.Unix(1201480721, 0)),
					},
				},
				TaskEnd: []Task{
					{
						Time:      Timestamp(time.Unix(1201479014, 0)),
						Task:      "Ping Scan",
						ExtraInfo: "8 total hosts",
					},
					{
						Time: Timestamp(time.Unix(1201479015, 0)),
						Task: "Parallel DNS resolution of 8 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201479016, 0)),
						Task: "System CNAME DNS resolution of 4 hosts.",
					},
					{
						Time:      Timestamp(time.Unix(1201480878, 0)),
						Task:      "SYN Stealth Scan",
						ExtraInfo: "8570 total ports",
					},
					{
						Time:      Timestamp(time.Unix(1201480984, 0)),
						Task:      "Service scan",
						ExtraInfo: "20 services on 5 hosts",
					},
					{
						Time: Timestamp(time.Unix(1201481028, 0)),
						Task: "Traceroute",
					},
					{
						Time: Timestamp(time.Unix(1201481059, 0)),
						Task: "Traceroute",
					},
					{
						Time: Timestamp(time.Unix(1201481070, 0)),
						Task: "Parallel DNS resolution of 85 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201481086, 0)),
						Task: "System CNAME DNS resolution of 8 hosts.",
					},
					{
						Time: Timestamp(time.Unix(1201481197, 0)),
						Task: "SCRIPT ENGINE",
					},
				},
			},

			wantErr: require.NoError,
		},
	}

	for _, test := range tests {
		t.Run(test.inputFile, func(t *testing.T) {
			rawXML, err := os.ReadFile(test.inputFile)
			require.NoError(t, err)

			result, err := parse(rawXML)
			test.wantErr(t, err)

			compareResults(t, test.expectedResult, result)
		})
	}
}

func compareResults(t *testing.T, expected, got *Run) {
	if expected == nil {
		require.Nil(t, got)
		return
	}

	require.NotNil(t, got)
	if len(expected.Args) > 0 { // We don't care if there are extra args, no need to check.
		assert.Equal(t, expected.Args, got.Args, "unexpected arguments")
	}
	if expected.ProfileName != "" {
		assert.Equal(t, expected.ProfileName, got.ProfileName, "unexpected profile name")
	}
	if expected.Scanner != "" {
		assert.Equal(t, expected.Scanner, got.Scanner, "unexpected scanner")
	}
	if expected.StartStr != "" {
		assert.Equal(t, expected.StartStr, got.StartStr, "unexpected start string")
	}
	if expected.Debugging.Level != 0 {
		assert.Equal(t, expected.Debugging.Level, got.Debugging.Level, "unexpected debugging level")
	}
	if expected.ScanInfo.NumServices != 0 {
		assert.Equal(t, expected.ScanInfo.NumServices, got.ScanInfo.NumServices, "unexpected scan info num services")
	}
	if expected.ScanInfo.Protocol != "" {
		assert.Equal(t, expected.ScanInfo.Protocol, got.ScanInfo.Protocol, "unexpected scan info protocol")
	}
	if expected.ScanInfo.ScanFlags != "" {
		assert.Equal(t, expected.ScanInfo.ScanFlags, got.ScanInfo.ScanFlags, "unexpected scan info scan flags")
	}
	if expected.ScanInfo.Services != "" {
		assert.Equal(t, expected.ScanInfo.Services, got.ScanInfo.Services, "unexpected scan info services")
	}
	if expected.ScanInfo.Type != "" {
		assert.Equal(t, expected.ScanInfo.Type, got.ScanInfo.Type, "unexpected scan info type")
	}
	if !time.Time(expected.Start).IsZero() {
		assert.Equal(t, expected.Start, got.Start, "unexpected start time")
	}
	if len(expected.Targets) > 0 {
		assert.Equal(t, expected.Targets, got.Targets, "unexpected targets")
	}

	if len(expected.TaskBegin) > 0 {
		if assert.Len(t, got.TaskBegin, len(expected.TaskBegin), "unexpected tasks begin entries") {
			for idx := range expected.TaskBegin {
				if !time.Time(expected.TaskBegin[idx].Time).IsZero() {
					assert.Equalf(t, expected.TaskBegin[idx].Time, got.TaskBegin[idx].Time, "unexpected task begin time at index %d", idx)
				}
				if expected.TaskBegin[idx].Task != "" {
					assert.Equalf(t, expected.TaskBegin[idx].Task, got.TaskBegin[idx].Task, "unexpected task begin task at index %d", idx)
				}
				if expected.TaskBegin[idx].ExtraInfo != "" {
					assert.Equalf(t, expected.TaskBegin[idx].ExtraInfo, got.TaskBegin[idx].ExtraInfo, "unexpected task begin extra info at index %d", idx)
				}
			}
		}
	}

	if len(expected.TaskProgress) > 0 {
		if assert.Len(t, got.TaskProgress, len(expected.TaskProgress), "unexpected tasks progress entries") {
			for idx := range expected.TaskProgress {
				if expected.TaskProgress[idx].Percent != 0 {
					assert.Equalf(t, expected.TaskProgress[idx].Percent, got.TaskProgress[idx].Percent, "unexpected task progress percent at index %d", idx)
				}
				if expected.TaskProgress[idx].Remaining != 0 {
					assert.Equalf(t, expected.TaskProgress[idx].Remaining, got.TaskProgress[idx].Remaining, "unexpected task progress remaining at index %d", idx)
				}
				if expected.TaskProgress[idx].Task != "" {
					assert.Equalf(t, expected.TaskProgress[idx].Task, got.TaskProgress[idx].Task, "unexpected task progress task at index %d", idx)
				}
				if !time.Time(expected.TaskProgress[idx].Etc).IsZero() {
					assert.Equalf(t, expected.TaskProgress[idx].Etc, got.TaskProgress[idx].Etc, "unexpected task progress etc at index %d", idx)
				}
				if !time.Time(expected.TaskProgress[idx].Time).IsZero() {
					assert.Equalf(t, expected.TaskProgress[idx].Time, got.TaskProgress[idx].Time, "unexpected task progress time at index %d", idx)
				}
			}
		}
	}

	if len(expected.TaskEnd) > 0 {
		if assert.Len(t, got.TaskEnd, len(expected.TaskEnd), "unexpected tasks end entries") {
			for idx := range expected.TaskEnd {
				if !time.Time(expected.TaskEnd[idx].Time).IsZero() {
					assert.Equalf(t, expected.TaskEnd[idx].Time, got.TaskEnd[idx].Time, "unexpected task end time at index %d", idx)
				}
				if expected.TaskEnd[idx].Task != "" {
					assert.Equalf(t, expected.TaskEnd[idx].Task, got.TaskEnd[idx].Task, "unexpected task end task at index %d", idx)
				}
				if expected.TaskEnd[idx].ExtraInfo != "" {
					assert.Equalf(t, expected.TaskEnd[idx].ExtraInfo, got.TaskEnd[idx].ExtraInfo, "unexpected task end extra info at index %d", idx)
				}
			}
		}
	}

	if len(expected.Hosts) == 0 {
		return
	}
	if !assert.Len(t, got.Hosts, len(expected.Hosts), "unexpected number of hosts") {
		return
	}

	for idx := range expected.Hosts {
		if expected.Hosts[idx].Comment != "" {
			assert.Equalf(t, expected.Hosts[idx].Comment, got.Hosts[idx].Comment, "unexpected host comment at index %d", idx)
		}
		if len(expected.Hosts[idx].Addresses) > 0 {
			assert.Equalf(t, expected.Hosts[idx].Addresses, got.Hosts[idx].Addresses, "unexpected host addresses at index %d", idx)
		}
		if expected.Hosts[idx].Distance.Value != 0 {
			assert.Equalf(t, expected.Hosts[idx].Distance.Value, got.Hosts[idx].Distance.Value, "unexpected host distance at index %d", idx)
		}
		if !time.Time(expected.Hosts[idx].EndTime).IsZero() {
			assert.Equalf(t, expected.Hosts[idx].EndTime, got.Hosts[idx].EndTime, "unexpected host end time at index %d", idx)
		}
		if len(expected.Hosts[idx].ExtraPorts) > 0 {
			assert.Equalf(t, expected.Hosts[idx].ExtraPorts, got.Hosts[idx].ExtraPorts, "unexpected host extra ports at index %d", idx)
		}
		if len(expected.Hosts[idx].HostScripts) > 0 {
			assert.Equalf(t, expected.Hosts[idx].HostScripts, got.Hosts[idx].HostScripts, "unexpected host host scripts at index %d", idx)
		}
		if len(expected.Hosts[idx].Hostnames) > 0 {
			assert.Equalf(t, expected.Hosts[idx].Hostnames, got.Hosts[idx].Hostnames, "unexpected host host names at index %d", idx)
		}
		if expected.Hosts[idx].IPIDSequence.Class != "" {
			assert.Equalf(t, expected.Hosts[idx].IPIDSequence.Class, got.Hosts[idx].IPIDSequence.Class, "unexpected host IPIDSequence class at index %d", idx)
		}
		if expected.Hosts[idx].IPIDSequence.Values != "" {
			assert.Equalf(t, expected.Hosts[idx].IPIDSequence.Values, got.Hosts[idx].IPIDSequence.Values, "unexpected host IPIDSequence values at index %d", idx)
		}

		if len(expected.Hosts[idx].OS.PortsUsed) > 0 {
			assert.Equalf(t, expected.Hosts[idx].OS.PortsUsed, got.Hosts[idx].OS.PortsUsed, "unexpected host ports used at index %d", idx)
		}
		if len(expected.Hosts[idx].OS.Fingerprints) > 0 {
			assert.Equalf(t, expected.Hosts[idx].OS.Fingerprints, got.Hosts[idx].OS.Fingerprints, "unexpected host os fingerprints at index %d", idx)
		}

		if len(expected.Hosts[idx].Ports) > 0 {
			assert.Equalf(t, expected.Hosts[idx].Ports, got.Hosts[idx].Ports, "unexpected host ports at index %d", idx)
		}
		if len(expected.Hosts[idx].Smurfs) > 0 {
			assert.Equalf(t, expected.Hosts[idx].Smurfs, got.Hosts[idx].Smurfs, "unexpected host smurfs at index %d", idx)
		}
		if !time.Time(expected.Hosts[idx].StartTime).IsZero() {
			assert.Equalf(t, expected.Hosts[idx].StartTime, got.Hosts[idx].StartTime, "unexpected host start time at index %d", idx)
		}
		if expected.Hosts[idx].TimedOut {
			assert.Equalf(t, expected.Hosts[idx].TimedOut, got.Hosts[idx].TimedOut, "unexpected host timedout at index %d", idx)
		}
		if expected.Hosts[idx].Status.State != "" {
			assert.Equalf(t, expected.Hosts[idx].Status.State, got.Hosts[idx].Status.State, "unexpected host status state at index %d", idx)
		}
		if expected.Hosts[idx].Status.Reason != "" {
			assert.Equalf(t, expected.Hosts[idx].Status.Reason, got.Hosts[idx].Status.Reason, "unexpected host status reason at index %d", idx)
		}
		if expected.Hosts[idx].Status.ReasonTTL != 0 {
			assert.Equalf(t, expected.Hosts[idx].Status.ReasonTTL, got.Hosts[idx].Status.ReasonTTL, "unexpected host status reason TTL at index %d", idx)
		}
		if expected.Hosts[idx].TCPSequence.Index != 0 {
			assert.Equalf(t, expected.Hosts[idx].TCPSequence.Index, got.Hosts[idx].TCPSequence.Index, "unexpected host TCPSequence index at index %d", idx)
		}
		if expected.Hosts[idx].TCPSequence.Difficulty != "" {
			assert.Equalf(t, expected.Hosts[idx].TCPSequence.Difficulty, got.Hosts[idx].TCPSequence.Difficulty, "unexpected host TCPSequence difficulty at index %d", idx)
		}
		if expected.Hosts[idx].TCPSequence.Values != "" {
			assert.Equalf(t, expected.Hosts[idx].TCPSequence.Values, got.Hosts[idx].TCPSequence.Values, "unexpected host TCPSequence values at index %d", idx)
		}
		if expected.Hosts[idx].TCPTSSequence.Class != "" {
			assert.Equalf(t, expected.Hosts[idx].TCPTSSequence.Class, got.Hosts[idx].TCPTSSequence.Class, "unexpected host TCPTSSequence class at index %d", idx)
		}
		if expected.Hosts[idx].TCPTSSequence.Values != "" {
			assert.Equalf(t, expected.Hosts[idx].TCPTSSequence.Values, got.Hosts[idx].TCPTSSequence.Values, "unexpected host TCPTSSequence values at index %d", idx)
		}
		if expected.Hosts[idx].Times.SRTT != "" {
			assert.Equalf(t, expected.Hosts[idx].Times.SRTT, got.Hosts[idx].Times.SRTT, "unexpected host times SRTT at index %d", idx)
		}
		if expected.Hosts[idx].Times.RTT != "" {
			assert.Equalf(t, expected.Hosts[idx].Times.RTT, got.Hosts[idx].Times.RTT, "unexpected host times RTT at index %d", idx)
		}
		if expected.Hosts[idx].Times.To != "" {
			assert.Equalf(t, expected.Hosts[idx].Times.To, got.Hosts[idx].Times.To, "unexpected host times To at index %d", idx)
		}
		if expected.Hosts[idx].Trace.Proto != "" {
			assert.Equalf(t, expected.Hosts[idx].Trace.Proto, got.Hosts[idx].Trace.Proto, "unexpected host trace proto at index %d", idx)
		}
		if expected.Hosts[idx].Trace.Port != 0 {
			assert.Equalf(t, expected.Hosts[idx].Trace.Port, got.Hosts[idx].Trace.Port, "unexpected host trace port at index %d", idx)
		}
		if len(expected.Hosts[idx].Trace.Hops) > 0 {
			assert.Equalf(t, expected.Hosts[idx].Trace.Hops, got.Hosts[idx].Trace.Hops, "unexpected host trace hops at index %d", idx)
		}
		if expected.Hosts[idx].Uptime.Seconds != 0 {
			assert.Equalf(t, expected.Hosts[idx].Uptime.Seconds, got.Hosts[idx].Uptime.Seconds, "unexpected host uptime seconds at index %d", idx)
		}
		if expected.Hosts[idx].Uptime.Lastboot != "" {
			assert.Equalf(t, expected.Hosts[idx].Uptime.Lastboot, got.Hosts[idx].Uptime.Lastboot, "unexpected host uptime lastboot at index %d", idx)
		}

		if len(expected.Hosts[idx].OS.Matches) == 0 {
			continue
		}
		if assert.Len(t, got.Hosts[idx].OS.Matches, len(expected.Hosts[idx].OS.Matches), "unexpected number of host matches at index %d", idx) {
			for i := range expected.Hosts[idx].OS.Matches {
				if expected.Hosts[idx].OS.Matches[i].Name != "" {
					assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Name, got.Hosts[idx].OS.Matches[i].Name, "unexpected host os match name at index %d match %d", idx, i)
				}
				if expected.Hosts[idx].OS.Matches[i].Accuracy != 0 {
					assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Accuracy, got.Hosts[idx].OS.Matches[i].Accuracy, "unexpected host os match accuracy at index %d match %d", idx, i)
				}
				if expected.Hosts[idx].OS.Matches[i].Line != 0 {
					assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Line, got.Hosts[idx].OS.Matches[i].Line, "unexpected host os match line at index %d match %d", idx, i)
				}

				if len(expected.Hosts[idx].OS.Matches[i].Classes) > 0 {
					if assert.Len(t, got.Hosts[idx].OS.Matches[i].Classes, len(expected.Hosts[idx].OS.Matches[i].Classes), "unexpected number of host classes at index %d match %d", idx, i) {
						for j := range expected.Hosts[idx].OS.Matches[i].Classes {
							if expected.Hosts[idx].OS.Matches[i].Classes[j].Vendor != "" {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].Vendor, got.Hosts[idx].OS.Matches[i].Classes[j].Vendor, "unexpected host os class vendor at index %d match %d class %d", idx, i, j)
							}
							if expected.Hosts[idx].OS.Matches[i].Classes[j].OSGeneration != "" {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].OSGeneration, got.Hosts[idx].OS.Matches[i].Classes[j].OSGeneration, "unexpected host os class os generation at index %d match %d class %d", idx, i, j)
							}
							if expected.Hosts[idx].OS.Matches[i].Classes[j].Type != "" {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].Type, got.Hosts[idx].OS.Matches[i].Classes[j].Type, "unexpected host os class type at index %d match %d class %d", idx, i, j)
							}
							if expected.Hosts[idx].OS.Matches[i].Classes[j].Accuracy != 0 {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].Accuracy, got.Hosts[idx].OS.Matches[i].Classes[j].Accuracy, "unexpected host os class accuracy at index %d match %d class %d", idx, i, j)
							}
							if expected.Hosts[idx].OS.Matches[i].Classes[j].Family != "" {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].Family, got.Hosts[idx].OS.Matches[i].Classes[j].Family, "unexpected host os class family at index %d match %d class %d", idx, i, j)
							}
							if len(expected.Hosts[idx].OS.Matches[i].Classes[j].CPEs) > 0 {
								assert.Equalf(t, expected.Hosts[idx].OS.Matches[i].Classes[j].CPEs, got.Hosts[idx].OS.Matches[i].Classes[j].CPEs, "unexpected host os class CPEs at index %d match %d class %d", idx, i, j)
							}
						}
					}
				}
			}
		}
	}
}

const fingerprint = "SCAN(V=4.53%D=1/27%OT=80%CT=443%CU=%PV=N%G=N%TM=479D25ED%P=i686-pc-linux-gnu)\nSEQ(SP=F2%GCD=1%ISR=E9%TI=Z%TS=1C)\nOPS(O1=M5B4ST11NW0%O2=M5B4ST11NW0%O3=M5B4NNT11NW0%O4=M5B4ST11NW0%O5=M5B4ST11NW0%O6=M5B4ST11)\nWIN(W1=16A0%W2=16A0%W3=16A0%W4=16A0%W5=16A0%W6=16A0)\nECN(R=Y%DF=Y%TG=40%W=16D0%O=M5B4NNSNW0%CC=N%Q=)\nT1(R=Y%DF=Y%TG=40%S=O%A=S+%F=AS%RD=0%Q=)\nT2(R=N)\nT3(R=Y%DF=Y%TG=40%W=16A0%S=O%A=S+%F=AS%O=M5B4ST11NW0%RD=0%Q=)\nT4(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)\nT5(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)\nT6(R=Y%DF=Y%TG=40%W=0%S=A%A=Z%F=R%O=%RD=0%Q=)\nT7(R=Y%DF=Y%TG=40%W=0%S=Z%A=S+%F=AR%O=%RD=0%Q=)\nU1(R=N)\nIE(R=N)\n"
