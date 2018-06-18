package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
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
				if ok, err := ValidateCertificate(ctx, myacm, *cert.CertificateArn); err != nil {
					log.Println("failed to describe certificate", err, *cert.CertificateArn)
				} else if ok {
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

// ValidateCertificate validates the certificate.
func ValidateCertificate(ctx context.Context, myacm *acm.ACM, arn string) (bool, error) {
	input := &acm.DescribeCertificateInput{
		CertificateArn: aws.String(arn),
	}
	output, err := myacm.DescribeCertificateWithContext(ctx, input)
	if err != nil {
		return false, err
	}

	allok := true
	cert := output.Certificate
	if opts := cert.DomainValidationOptions; opts != nil {
		for _, opt := range opts {
			if opt.ValidationMethod == nil {
				return false, errors.New("validation method is missing")
			}
			switch *opt.ValidationMethod {
			case "DNS":
				record := opt.ResourceRecord
				v, err := lookup(ctx, *record.Type, *record.Name)
				if err != nil {
					allok = false
					log.Printf("failed to validate %s: %s", *opt.DomainName, err)
				}
				if v != *record.Value {
					allok = false
					log.Printf("failed to validate %s", *opt.DomainName)
				}

			case "EMAIL":
				domains := GetValidationDomains(*opt.DomainName)
				ok := false
				for _, d := range domains {
					serial, err := GetSerialNumber(fmt.Sprintf("https://%s/", d))
					if err != nil {
						continue
					}
					if cert.Serial != nil && serial == *cert.Serial {
						ok = true
						break
					}
				}
				if !ok {
					allok = false
					log.Printf("failed to validate %s", *opt.DomainName)
				}
			}
		}
		return allok, nil
	}

	for _, name := range cert.SubjectAlternativeNames {
		domains := GetValidationDomains(*name)
		ok := false
		for _, d := range domains {
			serial, err := GetSerialNumber(fmt.Sprintf("https://%s/", d))
			if err != nil {
				continue
			}
			if cert.Serial != nil && serial == *cert.Serial {
				ok = true
				break
			}
		}
		if !ok {
			allok = false
			log.Printf("failed to validate %s", *name)
		}
	}
	return allok, nil
}

// Use Google Public DNS over HTTPS
func lookup(ctx context.Context, typ, name string) (string, error) {
	type answer struct {
		Question []*struct {
			Name string `json:"name"`
			Type int    `json:"type"`
		} `json:"Question"`
		Answer []*struct {
			Name string `json:"name"`
			Type int    `json:"type"`
			Data string `json:"data"`
		}
	}

	q := url.Values{}
	q.Set("type", typ)
	q.Set("name", name)
	u := &url.URL{
		Scheme:   "https",
		Host:     "dns.google.com",
		Path:     "/resolve",
		RawQuery: q.Encode(),
	}
	req, err := http.NewRequest(http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req = req.WithContext(ctx)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var ans answer
	dec := json.NewDecoder(resp.Body)
	if err := dec.Decode(&ans); err != nil {
		return "", err
	}
	return ans.Answer[0].Data, nil
}

// GetValidationDomains returns the domains that the checker validates.
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
