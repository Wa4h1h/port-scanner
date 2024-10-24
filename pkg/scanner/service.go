package scanner

import (
	"bytes"
	_ "embed"
	"encoding/csv"
	"fmt"
)

//go:embed assets/service-names-port-numbers.csv
var svcNamesPort []byte

var services map[string]string

func init() {
	services = make(map[string]string)
	r := bytes.NewReader(svcNamesPort)
	reader := csv.NewReader(r)

	recs, err := reader.ReadAll()
	if err != nil {
		panic(fmt.Errorf("error: read service-names-port-numbers.csv %w", err))
	}

	for _, row := range recs[1:] {
		port := row[1]
		proto := row[2]
		key := fmt.Sprintf("%s/%s", port, proto)
		_, ok := services[key]

		if !ok && row[0] != "" {
			services[key] = row[0]
		}
	}
}

func PortToService(descriptivePort string) string {
	s, ok := services[descriptivePort]

	if !ok {
		s = descriptivePort
	}

	return s
}
