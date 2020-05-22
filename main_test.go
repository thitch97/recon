package main_test

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"os"
	"os/exec"
	"testing"

	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gbytes"
	"github.com/onsi/gomega/gexec"
	"github.com/sclevine/spec"
	"github.com/sclevine/spec/report"
)

var entrypoint string

func TestVet(t *testing.T) {
	RegisterTestingT(t)
	var Expect = NewWithT(t).Expect

	var err error
	entrypoint, err = gexec.Build("github.com/thitch97/vet")
	Expect(err).NotTo(HaveOccurred())

	spec.Run(t, "vet", func(t *testing.T, context spec.G, it spec.S) {

		var (
			Expect = NewWithT(t).Expect
		)

		context("when given a file to upload", func() {

			var (
				api      *httptest.Server
				requests []*http.Request
				file     *os.File
			)

			it.Before(func() {

				var err error
				file, err = ioutil.TempFile("/tmp", "some-file")
				Expect(err).NotTo(HaveOccurred())

				err = os.Setenv("VIRUSTOTAL_API_KEY", "some-virustotal-token")
				Expect(err).ToNot(HaveOccurred())

				requests = []*http.Request{}
				api = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					dump, _ := httputil.DumpRequest(req, true)
					receivedRequest, _ := http.ReadRequest(bufio.NewReader(bytes.NewBuffer(dump)))

					requests = append(requests, receivedRequest)

					if req.Header.Get("x-apikey") != "some-virustotal-token" {
						w.WriteHeader(http.StatusForbidden)
						return
					}

					switch req.URL.Path {
					case "/files":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(`{
  "data": {
    "type": "analysis",
    "id": "some-analysis-id"
  }
}
`))
					case "/analyses/some-analysis-id":
						w.WriteHeader(http.StatusOK)
						w.Write([]byte(
							`{
    "data": {
        "attributes": {
            "date": 1588374580,
            "stats": {
                "confirmed-timeout": 0,
                "failure": 1,
                "harmless": 2,
                "malicious": 3,
                "suspicious": 4,
                "timeout": 5,
                "type-unsupported": 15,
                "undetected": 6
            },
            "status": "completed"
        },
        "type": "analysis"
    },
    "meta": {
        "file_info": {
            "md5": "some-md5",
            "name": "some-file",
            "sha256": "some-sha256",
            "size": 6218689
        }
    }
}`))

					default:
						t.Fatal(fmt.Sprintf("unknown request: %s", dump))
					}
				}))
			})

			it("outputs the stats of a file analysis", func() {
				command := exec.Command(
					entrypoint,
					"--endpoint", api.URL,
					"--file", file.Name(),
				)

				buffer := gbytes.NewBuffer()

				session, err := gexec.Start(command, buffer, buffer)
				Expect(err).NotTo(HaveOccurred())

				Eventually(session).Should(gexec.Exit(0), func() string { return fmt.Sprintf("output:\n%s\n", buffer.Contents()) })

				Expect(buffer).To(gbytes.Say(`Analysis ID: some-analysis-id`))
				Expect(buffer).To(gbytes.Say(`Status: completed`))

				Expect(buffer).To(gbytes.Say(`====== File Info ======`))
				Expect(buffer).To(gbytes.Say(`Name: some-file`))
				Expect(buffer).To(gbytes.Say(`SHA256: some-sha256`))

				Expect(buffer).To(gbytes.Say(`====== Statistics ======`))

				Expect(requests).To(HaveLen(2))

				uploadRequest := requests[0]
				Expect(uploadRequest.Method).To(Equal("POST"))
				Expect(uploadRequest.URL.Path).To(Equal("/files"))

				analysisRequest := requests[1]
				Expect(analysisRequest.Method).To(Equal("GET"))
				Expect(analysisRequest.URL.Path).To(Equal("/analyses/some-analysis-id"))

				Expect(buffer).To(gbytes.Say(`Failure: 1`))
				Expect(buffer).To(gbytes.Say(`Harmless: 2`))
				Expect(buffer).To(gbytes.Say(`Malicious: 3`))
				Expect(buffer).To(gbytes.Say(`Suspicious: 4`))
				Expect(buffer).To(gbytes.Say(`Timeout: 5`))
				Expect(buffer).To(gbytes.Say(`Undetected: 6`))
			})

			it.After(func() {
				api.Close()
			})
		})

	}, spec.Report(report.Terminal{}), spec.Parallel())

}
