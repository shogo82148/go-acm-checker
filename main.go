package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/acm"
)

func main() {
	regions := []string{
		"us-east-1", "us-east-2",
		"us-west-1", "us-west-2",
		"ap-south-1",
		"ap-southeast-1", "ap-southeast-2",
		"ap-northeast-1", "ap-northeast-2",
		"ca-central-1",
		"eu-central-1",
		"eu-west-1", "eu-west-2",
		"sa-east-1",
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, r := range regions {
		c := aws.NewConfig().WithRegion(r)
		s := session.Must(session.NewSession(c))
		myacm := acm.New(s, c)
		input := &acm.ListCertificatesInput{}
		err := myacm.ListCertificatesPagesWithContext(ctx, input, func(page *acm.ListCertificatesOutput, lastPage bool) bool {
			for _, cert := range page.CertificateSummaryList {
				input := &acm.DescribeCertificateInput{
					CertificateArn: cert.CertificateArn,
				}
				output, err := myacm.DescribeCertificateWithContext(ctx, input)
				if err != nil {
					log.Println("failed to describe certificate", err, *cert.CertificateArn)
					return true
				}
				cert := output.Certificate
				allok := true
				for _, name := range cert.SubjectAlternativeNames {
					domains := GetValidationDomains(*name)
					ok := false
					for _, d := range domains {
						serial, err := GetSerialNumber(fmt.Sprintf("https://%s/", d))
						if err != nil {
							continue
						}
						if serial == *cert.Serial {
							ok = true
							break
						}
					}
					if !ok {
						allok = false
						log.Printf("failed to validate %s", *name)
					}
				}
				if allok {
					log.Printf("success to validate %s(%s)", *cert.DomainName, *cert.CertificateArn)
				} else {
					log.Printf("failed to validate %s(%s)", *cert.DomainName, *cert.CertificateArn)
				}
			}
			return true
		})
		if err != nil {
			log.Println("failed to list certificates", err)
		}
	}
}

func GetValidationDomains(s string) []string {
	switch {
	case strings.HasPrefix(s, "www."):
		return []string{s, s[4:]}
	case strings.HasPrefix(s, "*."):
		return []string{s[2:], "www." + s[2:]}
	}
	return []string{s, "www." + s}
}

var myClient = &http.Client{
	Timeout: 30 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// GetSerialNumber gets the serial number of tls certification.
func GetSerialNumber(u string) (string, error) {
	resp, err := myClient.Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	io.Copy(ioutil.Discard, resp.Body)

	tls := resp.TLS
	if tls == nil {
		return "", errors.New("no tls state")
	}
	certs := tls.PeerCertificates
	if len(certs) == 0 {
		return "", errors.New("no certification")
	}
	serial := certs[0].SerialNumber.Bytes()
	s := make([]string, 0, len(serial))
	for _, b := range serial {
		s = append(s, fmt.Sprintf("%02x", b))
	}
	return strings.Join(s, ":"), nil
}
