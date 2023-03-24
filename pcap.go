package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Key interface{}

type Row struct {
	key            Key
	Count          int64
	Volume         int64
	RelativeCount  float64
	RelativeVolume float64
}

type DecoratedPacket struct {
	packet   gopacket.Packet
	metadata Metadata
}

func processData(decoratedPacketChannel <-chan DecoratedPacket,
	constructKey func(gopacket.Packet, Metadata) Key,
	NilKey func() Key,
	stringify func(Key) []string) [][]string {

	counter := make(map[Key]*Row)

	total_packets := int64(0)
	total_length := int64(0)

	for decoratedPacket := range decoratedPacketChannel {
		packet := decoratedPacket.packet
		metadata := decoratedPacket.metadata

		if packet == nil {
			fmt.Println("broken")
			continue
		}

		total_packets++
		total_length += int64(len(packet.Data()))

		key := constructKey(packet, metadata)
		if counter[key] == nil {
			counter[key] = &Row{key: key}
		}
		counter[key].Count++
		counter[key].Volume += int64(len(packet.Data()))
	}

	table := make([][]string, 0, len(counter))
	keys := make([]Key, 0, len(counter))

	for _, row := range counter {
		row.RelativeCount = float64(row.Count) / float64(total_packets)
		row.RelativeVolume = float64(row.Volume) / float64(total_length)
	}

	for key := range counter {
		keys = append(keys, key)
	}

	sort.SliceStable(keys, func(i, j int) bool {
		return counter[keys[i]].Count > counter[keys[j]].Count
	})

	for idx, key := range keys {
		row := append(
			stringify(key),
			[]string{
				fmt.Sprint((*counter[key]).Count),
				fmt.Sprint((*counter[key]).Volume),
				fmt.Sprintf("%.6f", (*counter[key]).RelativeCount),
				fmt.Sprintf("%.6f", (*counter[key]).RelativeVolume),
			}...,
		)
		table = append(table, row)
		if idx < 10 {
			fmt.Println(row)
		}
	}

	return table
}

func VolumeByProtocolPort(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "volume_by_protocol_port.csv"
	header := []string{"Protocol", "Port", "Count", "Volume", "RelativeCount", "RelativeVolume"}
	type MyKey struct {
		Key
		Protocol string
		Port     int
	}

	NilKey := func() Key {
		return MyKey{Protocol: "default", Port: int(-1)}
	}
	stringify := func(key Key) []string {
		return []string{key.(MyKey).Protocol, fmt.Sprintf("%d", key.(MyKey).Port)}
	}

	layerClass := gopacket.NewLayerClass([]gopacket.LayerType{layers.LayerTypeTCP, layers.LayerTypeUDP, layers.LayerTypeICMPv4})

	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		key := MyKey{Protocol: packet.NetworkLayer().(*layers.IPv4).Protocol.String(), Port: -1}

		layer := packet.LayerClass(layerClass)
		if layer != nil {
			switch layer.LayerType() {
			case layers.LayerTypeTCP:
				key.Port = int(layer.(*layers.TCP).DstPort)
				return key

			case layers.LayerTypeUDP:
				key.Port = int(layer.(*layers.UDP).DstPort)
				return key

			case layers.LayerTypeICMPv4:
				key.Port = int(layer.(*layers.ICMPv4).TypeCode)
				return key

			}
		}
		return key

	}
	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}
	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func VolumeBySourceCountry(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "volume_by_source_country.csv"
	header := []string{"NetacqCountry", "MaxmindCountry", "Count", "Volume", "RelativeCount", "RelativeVolume"}

	type MyKey struct {
		NetacqCountry  string
		MaxmindCountry string
	}
	stringify := func(key Key) []string {
		return []string{
			key.(MyKey).NetacqCountry,
			key.(MyKey).MaxmindCountry,
		}
	}
	NilKey := func() Key {
		return MyKey{NetacqCountry: "unknown", MaxmindCountry: "unknown"}
	}
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		return MyKey{NetacqCountry: metadata.NetacqCountry, MaxmindCountry: metadata.MaxmindCountry}
	}
	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}

	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func VolumeBySourceAS(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "volume_by_source_as.csv"

	type MyKey struct {
		SrcASN string
	}

	header := []string{"SrcASN", "Count", "Volume", "RelativeCount", "RelativeVolume"}

	stringify := func(key Key) []string {
		return []string{
			key.(MyKey).SrcASN,
		}
	}
	NilKey := func() Key {
		return MyKey{SrcASN: "-1"}
	}
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		return MyKey{SrcASN: metadata.SrcASN}
	}
	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}

	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func ScannerAnalysis(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "scanning_campaign.csv"

	type MyKey struct {
		Scanner  string
		Protocol string
		Port     int
	}

	header := []string{"Scanner", "Protocol", "Port", "Count", "Volume", "RelativeCount", "RelativeVolume"}

	stringify := func(key Key) []string {
		return []string{
			key.(MyKey).Scanner,
			key.(MyKey).Protocol,
			fmt.Sprint(key.(MyKey).Port),
		}
	}
	NilKey := func() Key {
		return MyKey{Scanner: "", Protocol: "", Port: -1}
	}
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		layerClass := gopacket.NewLayerClass([]gopacket.LayerType{layers.LayerTypeTCP, layers.LayerTypeUDP})

		layer := packet.LayerClass(layerClass)
		if layer == nil {
			return NilKey()
		}
		protocol := ""
		port := -1
		switch layer.LayerType() {
		case layers.LayerTypeTCP:
			tcp, _ := layer.(*layers.TCP)
			protocol = layer.LayerType().String()
			port = int(tcp.DstPort)
			break

		case layers.LayerTypeUDP:
			udp, _ := layer.(*layers.UDP)
			protocol = layer.LayerType().String()
			port = int(udp.DstPort)
			break
		}
		// port := layer

		if metadata.KnownScanner != "" {
			return MyKey{Scanner: metadata.KnownScanner, Protocol: protocol, Port: port}
		} else if metadata.IsBogon {
			return MyKey{Scanner: "Bogon", Protocol: protocol, Port: port}
		} else if metadata.IsMasscan {
			return MyKey{Scanner: "Masscan", Protocol: protocol, Port: port}
		} else if metadata.IsMirai {
			return MyKey{Scanner: "Mirai", Protocol: protocol, Port: port}
		} else if metadata.IsZmap {
			return MyKey{Scanner: "ZMap", Protocol: protocol, Port: port}
		}
		return NilKey()
	}

	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}

	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func TimeSeriesHourCountry(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "time_series_hour_country.csv"

	type MyKey struct {
		Date           string
		NetacqCountry  string
		MaxmindCountry string
	}

	header := []string{"Date", "NetacqCountry", "MaxmindCountry", "Count", "Volume", "RelativeCount", "RelativeVolume"}

	stringify := func(key Key) []string {
		return []string{
			key.(MyKey).Date,
			key.(MyKey).NetacqCountry,
			key.(MyKey).MaxmindCountry,
		}
	}
	NilKey := func() Key {
		return MyKey{Date: "", NetacqCountry: "unknown", MaxmindCountry: "unknown"}
	}
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		return MyKey{Date: packet.Metadata().Timestamp.Truncate(time.Hour).String(), NetacqCountry: metadata.NetacqCountry, MaxmindCountry: metadata.MaxmindCountry}
	}

	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}

	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func InternetBackscatter(decoratedPacketChannel <-chan DecoratedPacket) (string, []string, [][]string) {
	filename := "internet_backscatter.csv"

	type MyKey struct {
		dest_ip string
		ASN     string
	}

	header := []string{"dest_ip", "ASN", "Count", "Volume", "RelativeCount", "RelativeVolume"}

	stringify := func(key Key) []string {
		return []string{
			key.(MyKey).dest_ip,
			key.(MyKey).ASN,
		}
	}
	NilKey := func() Key {
		return MyKey{dest_ip: "", ASN: ""}
	}
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		layerClass := gopacket.NewLayerClass([]gopacket.LayerType{layers.LayerTypeTCP})

		layer := packet.LayerClass(layerClass)
		if layer == nil {
			return NilKey()
		}
		if layer.LayerType() == layers.LayerTypeTCP {
			tcp, ok := layer.(*layers.TCP)
			if ok && (tcp.ACK || tcp.RST) {
				return MyKey{
					dest_ip: packet.Layer(layers.LayerTypeIPv4).(*layers.IPv4).SrcIP.String(),
					ASN:     metadata.SrcASN,
				}
			}
		}
		return NilKey()
	}

	if len(stringify(NilKey())) != len(header)-4 {
		panic("header length does not match key length")
	}

	return filename, header, processData(decoratedPacketChannel, constructKey, NilKey, stringify)
}

func WriteCsv(filename string, header []string, table [][]string) {
	f, err := os.Create("data/processed/" + filename)
	defer f.Close()

	if err != nil {
		fmt.Println("failed to open file", err)
	}

	w := csv.NewWriter(f)
	defer w.Flush()
	err = w.Write(header)

	if err != nil {
		log.Fatalln("error writing header to file", err)
	}
	for _, record := range table {
		err = w.Write(record)
		if err != nil {
			log.Fatalln("error writing record to file", err)
		}
	}
}

func loadData(fileNameWithoutExtension string,
	decoratedPacketChannel chan DecoratedPacket,
	waitGroup *sync.WaitGroup) {

	fmt.Print("o")
	defer fmt.Print("x")

	file, _ := os.Open("data/raw/metadata/" + fileNameWithoutExtension + ".json")

	handle, err := pcap.OpenOffline("data/raw/pcapsanon/" + fileNameWithoutExtension + ".pcap")
	if err != nil {
		fmt.Println("HERE" + err.Error())
	}
	decoder := json.NewDecoder(file)
	decoder.Token()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		metadata := Metadata{}
		_ = decoder.Decode(&metadata)

		decoratedPacketChannel <- DecoratedPacket{packet, metadata}
	}

	waitGroup.Done()
}

type Metadata struct {
	PacketCnt      int
	IsZmap         bool
	IsMasscan      bool
	IsMirai        bool
	IsBogon        bool
	SrcASN         string
	NetacqCountry  string
	MaxmindCountry string
	KnownScanner   string
}

func GetNameWithoutExtension(fileName string) string {
	return fileName[:len(fileName)-len(filepath.Ext(fileName))]
}

func run(processor func(<-chan DecoratedPacket) (string, []string, [][]string)) {
	files, _ := ioutil.ReadDir("data/raw/pcapsanon/")

	files = files[:]

	decoratedPacketChannel := make(chan DecoratedPacket)

	waitGroup := sync.WaitGroup{}
	waitGroup.Add(len(files))

	go func() {
		waitGroup.Wait()
		fmt.Println("\nclosing")
		close(decoratedPacketChannel)
	}()

	for i := 0; i < len(files); i++ {
		go loadData(GetNameWithoutExtension(files[i].Name()), decoratedPacketChannel, &waitGroup)
	}
	time.Sleep(time.Second)
	fmt.Println()

	filename, header, table := processor(decoratedPacketChannel)

	WriteCsv(filename, header, table)
}

func main() {

	processors := map[string]func(<-chan DecoratedPacket) (string, []string, [][]string){
		// "TimeSeriesHourCountry": TimeSeriesHourCountry,
		// "VolumeBySourceCountry": VolumeBySourceCountry,
		// "VolumeBySourceAS":      VolumeBySourceAS,
		"VolumeByProtocolPort": VolumeByProtocolPort,
		// "ScannerAnalysis":     ScannerAnalysis,
		// "InternetBackscatter": InternetBackscatter,
	}
	for name, processor := range processors {
		fmt.Println("running", name)
		run(processor)
	}
}
