package geoip

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2/log"
)

const (
	url4       = "https://iptoasn.com/data/ip2country-v4-u32.tsv.gz"
	url6       = "https://iptoasn.com/data/ip2country-v6.tsv.gz"
	cacheName4 = "cached_file.tsv.gz"
	cacheName6 = "cached_file6.tsv.gz"
	cacheTTL   = 12 * time.Hour
)

type GeoIP struct {
	dir   string
	mutex sync.RWMutex
	data4 []geoData4
	data6 []geoData6
}

type geoData4 struct {
	rangeStart  uint32
	rangeEnd    uint32
	countryCode string
}

type geoData6 struct {
	rangeStartLo uint64
	rangeStartHi uint64
	rangeEndLo   uint64
	rangeEndHi   uint64
	countryCode  string
}

func NewGeoIP(dir string, enableSchedule bool) *GeoIP {
	geoIP := &GeoIP{
		dir: dir,
	}
	if enableSchedule {
		geoIP.scheduledDownload()
	} else {
		geoIP.download4()
	}
	return geoIP
}

func (geoIP *GeoIP) Lookup(value string) (string, bool) {
	geoIP.download4()
	return geoIP.findCountry(value)
}

func (geoIP *GeoIP) scheduledDownload() {
	duration := cacheTTL + 10*time.Minute
	ticker := time.NewTicker(duration)
	go func() {
		geoIP.download4()
		geoIP.download6()
		log.Infof("Scheduled GeoIP download every %s", duration)
		for range ticker.C {
			geoIP.download4()
			geoIP.download6()
		}
	}()
}

func (geoIP *GeoIP) download4() {
	geoIP.mutex.Lock()
	defer geoIP.mutex.Unlock()

	filePath := filepath.Join(geoIP.dir, cacheName4)

	// Check if a file exists and is recent enough
	needDownload := true
	if stat, err := os.Stat(filePath); err == nil {
		if time.Since(stat.ModTime()) < cacheTTL {
			needDownload = false
		}
	}

	// Download the file if needed
	if needDownload {
		log.Infof("Downloading GeoIP IPv4 data from %s", url4)
		err := downloadFile(url4, filePath)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("Download IPv4 finished to %s", filePath)

		geoIP.data4 = loadDataFromFile4(filePath)
	} else if len(geoIP.data4) == 0 {
		geoIP.data4 = loadDataFromFile4(filePath)
	}
}

func (geoIP *GeoIP) download6() {
	geoIP.mutex.Lock()
	defer geoIP.mutex.Unlock()

	filePath := filepath.Join(geoIP.dir, cacheName6)

	// Check if a file exists and is recent enough
	needDownload := true
	if stat, err := os.Stat(filePath); err == nil {
		if time.Since(stat.ModTime()) < cacheTTL {
			needDownload = false
		}
	}

	// Download the file if needed
	if needDownload {
		log.Infof("Downloading GeoIP IPv6 data from %s", url6)
		err := downloadFile(url6, filePath)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("Download IPv6 finished to %s", filePath)

		geoIP.data6 = loadDataFromFile6(filePath)
	} else if len(geoIP.data6) == 0 {
		geoIP.data6 = loadDataFromFile6(filePath)
	}
}

func (geoIP *GeoIP) findCountry(value string) (string, bool) {
	geoIP.mutex.RLock()
	defer geoIP.mutex.RUnlock()
	if len(geoIP.data4) == 0 && len(geoIP.data6) == 0 {
		return "", false
	}
	parsedIP := net.ParseIP(value)
	if parsedIP == nil {
		return "", false
	}
	if parsedIP.To4() != nil && len(geoIP.data4) != 0 {
		return geoIP.findCountry4(parsedIP)
	} else if parsedIP.To16() != nil && len(geoIP.data6) != 0 {
		return geoIP.findCountry6(parsedIP)
	}

	return "", false
}

func (geoIP *GeoIP) findCountry4(parsedIP net.IP) (string, bool) {
	geoIP.mutex.RLock()
	defer geoIP.mutex.RUnlock()
	ip := parsedIP.To4()
	ipNum := binary.BigEndian.Uint32(ip)

	low, high := 0, len(geoIP.data4)-1
	for low <= high {
		mid := (low + high) / 2
		start := geoIP.data4[mid].rangeStart
		end := geoIP.data4[mid].rangeEnd

		switch {
		case ipNum < start:
			high = mid - 1
		case ipNum > end:
			low = mid + 1
		default:
			return geoIP.data4[mid].countryCode, true
		}
	}
	return "", false
}

func (geoIP *GeoIP) findCountry6(parsedIP net.IP) (string, bool) {
	geoIP.mutex.RLock()
	defer geoIP.mutex.RUnlock()

	ip := parsedIP.To16()
	if ip == nil || parsedIP.To4() != nil {
		return "", false
	}

	ipHi := binary.BigEndian.Uint64(ip[0:8])
	ipLo := binary.BigEndian.Uint64(ip[8:16])

	low, high := 0, len(geoIP.data6)-1
	for low <= high {
		mid := (low + high) / 2
		current := geoIP.data6[mid]

		switch {
		case compareIPv6(ipHi, ipLo, current.rangeStartHi, current.rangeStartLo) < 0:
			high = mid - 1
		case compareIPv6(ipHi, ipLo, current.rangeEndHi, current.rangeEndLo) > 0:
			low = mid + 1
		default:
			return current.countryCode, true
		}
	}

	return "", false
}

func loadDataFromFile4(filePath string) []geoData4 {
	log.Infof("Loading GeoIP IPv4 data from %s", filePath)
	data, err := readGzip4(filePath)
	if err != nil {
		log.Error(err)
		return []geoData4{}
	}

	log.Info("GeoIP IPv4 data loaded")
	return data
}

func loadDataFromFile6(filePath string) []geoData6 {
	log.Infof("Loading GeoIP IPv6 data from %s", filePath)

	data, err := readGzip6(filePath)
	if err != nil {
		log.Error(err)
		return []geoData6{}
	}

	log.Info("GeoIP IPv6 data loaded")
	return data
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		httpCloseError := Body.Close()
		if httpCloseError != nil {
			log.Error(httpCloseError)
		}
	}(resp.Body)

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer func(out *os.File) {
		fileCloseError := out.Close()
		if fileCloseError != nil {
			log.Error(fileCloseError)
		}
	}(out)

	_, err = io.Copy(out, resp.Body)
	return err
}

func readGzip4(filePath string) ([]geoData4, error) {
	return readGzip(filePath, func(record []string) (geoData4, bool) {
		if len(record) < 3 || record[2] == "None" {
			return geoData4{}, false
		}

		return geoData4{
			rangeStart:  toInt(record[0]),
			rangeEnd:    toInt(record[1]),
			countryCode: record[2],
		}, true
	})
}

func readGzip6(filePath string) ([]geoData6, error) {
	return readGzip(filePath, func(record []string) (geoData6, bool) {
		if len(record) < 3 || record[2] == "None" {
			return geoData6{}, false
		}

		startHi, startLo, startParseError := toUint64Pair(record[0])
		if startParseError != nil {
			return geoData6{}, false
		}

		endHi, endLo, endParseError := toUint64Pair(record[1])
		if endParseError != nil {
			return geoData6{}, false
		}

		return geoData6{
			rangeStartLo: startLo,
			rangeStartHi: startHi,
			rangeEndLo:   endLo,
			rangeEndHi:   endHi,
			countryCode:  record[2],
		}, true
	})
}

func readGzip[T any](filePath string, parseRecord func([]string) (T, bool)) ([]T, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return []T{}, err
	}
	defer func(f *os.File) {
		fileCloseError := f.Close()
		if fileCloseError != nil {
			log.Error(fileCloseError)
		}
	}(f)

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return []T{}, err
	}
	defer func(gzReader *gzip.Reader) {
		gzReaderCloseError := gzReader.Close()
		if gzReaderCloseError != nil {
			log.Error(gzReaderCloseError)
		}
	}(gzReader)

	tsvReader := csv.NewReader(gzReader)
	tsvReader.Comma = '\t'
	tsvReader.FieldsPerRecord = -1

	result := make([]T, 0)

	for {
		record, tsvError := tsvReader.Read()
		if tsvError == io.EOF {
			break
		}
		if tsvError != nil {
			return []T{}, tsvError
		}

		current, ok := parseRecord(record)
		if ok {
			result = append(result, current)
		}
	}

	return result, nil
}

func toInt(value string) uint32 {
	u64, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		panic(err)
	}
	return uint32(u64)
}

func toUint64Pair(s string) (hi, lo uint64, err error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return 0, 0, err
	}

	if !addr.Is6() {
		return 0, 0, fmt.Errorf("not an IPv6 address")
	}

	b := addr.As16()
	hi = binary.BigEndian.Uint64(b[0:8])
	lo = binary.BigEndian.Uint64(b[8:16])
	return hi, lo, nil
}

func compareIPv6(aHi, aLo, bHi, bLo uint64) int {
	switch {
	case aHi < bHi:
		return -1
	case aHi > bHi:
		return 1
	case aLo < bLo:
		return -1
	case aLo > bLo:
		return 1
	default:
		return 0
	}
}
