package main

import (
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
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

func processData(packetChannel <-chan gopacket.Packet,
	metadataChannel <-chan Metadata,
	constructKey func(gopacket.Packet, Metadata) Key,
	NilKey func() Key,
	stringify func(Key) []string) [][]string {

	counter := make(map[Key]*Row)

	total_packets := int64(0)
	total_length := int64(0)

	for packet := range packetChannel {
		metadata := <-metadataChannel

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

func ProtocolPortCounter(packetChannel <-chan gopacket.Packet, metadataChannel <-chan Metadata) (string, []string, [][]string) {
	filename := "protocol_port_counter.csv"
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
	constructKey := func(packet gopacket.Packet, metadata Metadata) Key {
		layerClass := gopacket.NewLayerClass([]gopacket.LayerType{layers.LayerTypeTCP, layers.LayerTypeUDP, layers.LayerTypeICMPv4})

		layer := packet.LayerClass(layerClass)
		if layer == nil {
			return NilKey()
		}
		switch layer.LayerType() {
		case layers.LayerTypeTCP:
			tcp, _ := layer.(*layers.TCP)
			key := MyKey{Protocol: "tcp", Port: int(tcp.DstPort)}
			return key

		case layers.LayerTypeUDP:
			udp, _ := layer.(*layers.UDP)
			key := MyKey{Protocol: "udp", Port: int(udp.DstPort)}
			return key

		case layers.LayerTypeICMPv4:
			icmp, _ := layer.(*layers.ICMPv4)
			key := MyKey{Protocol: "icmp", Port: int(icmp.TypeCode)}
			return key

		}
		return NilKey()
	}
	return filename, header, processData(packetChannel, metadataChannel, constructKey, NilKey, stringify)
}

func VolumeBySourceCountry(packetChannel <-chan gopacket.Packet, metadataChannel <-chan Metadata) (string, []string, [][]string) {
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

	return filename, header, processData(packetChannel, metadataChannel, constructKey, NilKey, stringify)
}

func VolumeBySourceAS(packetChannel <-chan gopacket.Packet, metadataChannel <-chan Metadata) (string, []string, [][]string) {
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

	return filename, header, processData(packetChannel, metadataChannel, constructKey, NilKey, stringify)
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

func loadPcaps(filepath string, packetChannel chan gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Print("o")
	defer fmt.Print("x")
	handle, err := pcap.OpenOffline(filepath)
	if err != nil {
		fmt.Println("HERE" + err.Error())
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		packetChannel <- packet
	}

}

func loadMetadata(filepath string, metadataChannel chan Metadata, wg *sync.WaitGroup) {
	defer wg.Done()

	fmt.Print("o")
	defer fmt.Print("x")

	file, _ := os.Open(filepath)

	decoder := json.NewDecoder(file)
	decoder.Token()

	for decoder.More() {
		metadata := Metadata{}
		_ = decoder.Decode(&metadata)
		metadataChannel <- metadata
	}

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

func main() {
	pcap, _ := ioutil.ReadDir("data/raw/pcapsanon/")
	metadata, _ := ioutil.ReadDir("data/raw/metadata/")
	packetChannel := make(chan gopacket.Packet, 0)
	metadataChannel := make(chan Metadata, 0)

	K := len(pcap)

	waitGroup := sync.WaitGroup{}
	// waitGroup.Add(len(pcap) + len(metadata))
	waitGroup.Add(K + K)

	go func() {
		waitGroup.Wait()
		fmt.Println("\nclosing")
		close(packetChannel)
		close(metadataChannel)
	}()

	for i := 0; i < K; i++ {
		go loadPcaps("data/raw/pcapsanon/"+pcap[i].Name(), packetChannel, &waitGroup)
		go loadMetadata("data/raw/metadata/"+metadata[i].Name(), metadataChannel, &waitGroup)
	}
	time.Sleep(time.Second)
	fmt.Println()

	fmt.Println(flag.Args())
	processor := VolumeBySourceAS

	filename, header, table := processor(packetChannel, metadataChannel)

	WriteCsv(filename, header, table)
}
