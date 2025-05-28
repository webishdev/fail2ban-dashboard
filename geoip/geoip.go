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
	"time"
)

const (
	url      = "https://iptoasn.com/data/ip2country-v4-u32.tsv.gz"
	tempName = "cached_file.tsv.gzx"
	cacheTTL = 12 * time.Hour
)

type GeoIP struct {
	data []geoData
}

type geoData struct {
	rangeStart  uint32
	rangeEnd    uint32
	countryCode string
}

func NewGeoIP() *GeoIP {
	return &GeoIP{}
}

func (geoip *GeoIP) Lookup(value string) (string, bool) {
	geoip.download()
	return geoip.findCountry(value)
}

func (geoip *GeoIP) download() {
	tmpDir := os.TempDir()
	filePath := filepath.Join(tmpDir, tempName)

	// Check if file exists and is recent enough
	needDownload := true
	if stat, err := os.Stat(filePath); err == nil {
		if time.Since(stat.ModTime()) < cacheTTL {
			needDownload = false
		}
	}

	// Download file if needed
	if needDownload {
		log.Infof("Downloading GeoIP data from %s", url)
		err := downloadFile(url, filePath)
		if err != nil {
			log.Error(err)
			return
		}

		data, err := readGzip(filePath)
		if err != nil {
			log.Error(err)
			return
		}

		geoip.data = data
	} else if len(geoip.data) == 0 {
		log.Infof("Loading GeoIP data from %s", filePath)
		data, err := readGzip(filePath)
		if err != nil {
			log.Error(err)
			return
		}

		geoip.data = data
	}
}

func (geoip *GeoIP) findCountry(value string) (string, bool) {
	if len(geoip.data) == 0 {
		return "", false
	}
	ipRegEx := regexp.MustCompile("^(?:[0-9]{1,3}\\.){3}[0-9]{1,3}$")
	isIPAddress := ipRegEx.MatchString(value)
	if !isIPAddress {
		return "", false
	}
	ip := net.ParseIP(value).To4()
	ipNum := binary.BigEndian.Uint32(ip)

	low, high := 0, len(geoip.data)-1
	for low <= high {
		mid := (low + high) / 2
		start := geoip.data[mid].rangeStart
		end := geoip.data[mid].rangeEnd

		switch {
		case ipNum < start:
			high = mid - 1
		case ipNum > end:
			low = mid + 1
		default:
			return geoip.data[mid].countryCode, true
		}
	}
	return "", false
}

func toInt(value string) uint32 {
	u64, err := strconv.ParseUint(value, 10, 32)
	if err != nil {
		panic(err)
	}
	return uint32(u64)
}

func downloadFile(url, dest string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	out, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func readGzip(filePath string) ([]geoData, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return []geoData{}, err
	}
	defer f.Close()

	gzReader, err := gzip.NewReader(f)
	if err != nil {
		return []geoData{}, err
	}
	defer gzReader.Close()

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
