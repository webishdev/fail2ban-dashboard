package geoip

import (
	"compress/gzip"
	"encoding/binary"
	"encoding/csv"
	"github.com/gofiber/fiber/v2/log"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"sync"
	"time"
)

const (
	url       = "https://iptoasn.com/data/ip2country-v4-u32.tsv.gz"
	cacheName = "cached_file.tsv.gz"
	cacheTTL  = 12 * time.Hour
)

type GeoIP struct {
	dir   string
	mutex sync.RWMutex
	data  []geoData
}

type geoData struct {
	rangeStart  uint32
	rangeEnd    uint32
	countryCode string
}

func NewGeoIP(dir string) *GeoIP {
	geoIP := &GeoIP{
		dir: dir,
	}
	go geoIP.download()
	return geoIP
}

func (geoIP *GeoIP) Lookup(value string) (string, bool) {
	geoIP.download()
	return geoIP.findCountry(value)
}

func (geoIP *GeoIP) download() {
	geoIP.mutex.Lock()
	defer geoIP.mutex.Unlock()

	filePath := filepath.Join(geoIP.dir, cacheName)

	// Check if a file exists and is recent enough
	needDownload := true
	if stat, err := os.Stat(filePath); err == nil {
		if time.Since(stat.ModTime()) < cacheTTL {
			needDownload = false
		}
	}

	// Download the file if needed
	if needDownload {
		log.Infof("Downloading GeoIP data from %s", url)
		err := downloadFile(url, filePath)
		if err != nil {
			log.Error(err)
			return
		}
		log.Infof("Download finished to %s", filePath)

		geoIP.data = loadDataFromFile(filePath)
	} else if len(geoIP.data) == 0 {
		geoIP.data = loadDataFromFile(filePath)
	}
}

func (geoIP *GeoIP) findCountry(value string) (string, bool) {
	geoIP.mutex.RLock()
	defer geoIP.mutex.RUnlock()
	if len(geoIP.data) == 0 {
		return "", false
	}
	ipRegEx := regexp.MustCompile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
	isIPAddress := ipRegEx.MatchString(value)
	if !isIPAddress {
		return "", false
	}
	ip := net.ParseIP(value).To4()
	ipNum := binary.BigEndian.Uint32(ip)

	low, high := 0, len(geoIP.data)-1
	for low <= high {
		mid := (low + high) / 2
		start := geoIP.data[mid].rangeStart
		end := geoIP.data[mid].rangeEnd

		switch {
		case ipNum < start:
			high = mid - 1
		case ipNum > end:
			low = mid + 1
		default:
			return geoIP.data[mid].countryCode, true
		}
	}
	return "", false
}

func loadDataFromFile(filePath string) []geoData {
	log.Infof("Loading GeoIP data from %s", filePath)
	data, err := readGzip(filePath)
	if err != nil {
		log.Error(err)
		return []geoData{}
	}

	log.Info("GeoIP data loaded")
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

func readGzip(filePath string) ([]geoData, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return []geoData{}, err
	}
	defer func(f *os.File) {
		fileCloseError := f.Close()
		if fileCloseError != nil {
			log.Error(fileCloseError)
		}
	}(f)

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return []geoData{}, err
	}
	defer func(gzReader *gzip.Reader) {
		gzReaderCloseError := gzReader.Close()
		if gzReaderCloseError != nil {
			log.Error(gzReaderCloseError)
		}
	}(gzReader)

	// Step 3: Create a TSV reader (CSV with tab delimiter)
	tsvReader := csv.NewReader(gzReader)
	tsvReader.Comma = '\t'         // Set delimiter to tab
	tsvReader.FieldsPerRecord = -1 // Optional: allow variable number of fields

	result := make([]geoData, 0)

	// Step 4: Read and process records
	for {
		record, tsvError := tsvReader.Read()
		if tsvError == io.EOF {
			break
		}
		if tsvError != nil {
			return []geoData{}, tsvError
		}

		if len(record) >= 2 && record[2] != "None" {
			current := geoData{
				rangeStart:  toInt(record[0]),
				rangeEnd:    toInt(record[1]),
				countryCode: record[2],
			}

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
