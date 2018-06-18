package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/service/acm"
	"github.com/aws/aws-sdk-go/service/acm/acmiface"
)

func TestGetValidationDomains(t *testing.T) {
	cases := []struct {
		input  string
		output []string
	}{
		// these test cases are from http://docs.aws.amazon.com/acm/latest/userguide/how-domain-validation-works.html
		{
			input:  "example.com",
			output: []string{"example.com", "www.example.com"},
		},
		{
			input:  "www.example.com",
			output: []string{"www.example.com", "example.com"},
		},
		{
			input:  "*.example.com",
			output: []string{"example.com", "www.example.com"},
		},
		{
			input:  "subdomain.example.com",
			output: []string{"subdomain.example.com", "www.subdomain.example.com"},
		},
		{
			input:  "www.subdomain.example.com",
			output: []string{"www.subdomain.example.com", "subdomain.example.com"},
		},
		{
			input:  "*.subdomain.example.com",
			output: []string{"subdomain.example.com", "www.subdomain.example.com"},
		},
	}

	for _, c := range cases {
		o := GetValidationDomains(c.input)
		sort.Strings(o)
		sort.Strings(c.output)
		if !reflect.DeepEqual(o, c.output) {
			t.Errorf("want %v, got %v", c.output, o)
		}
	}
}

func TestGetSerialNumber(t *testing.T) {
	myClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "Hello, client")
	}))
	defer ts.Close()

	serial, err := GetSerialNumber(ts.URL)
	if err != nil {
		t.Fatal(err)
	}
	want := "30:83:02:84:c2:c6:ad:1f:90:be:64:2f:a7:00:14:eb"
	if !strings.EqualFold(serial, want) {
		t.Errorf("want %s, got %s", want, serial)
	}
}

type mockACMClient struct {
	acmiface.ACMAPI
}

func (m *mockACMClient) DescribeCertificateWithContext(ctx aws.Context, input *acm.DescribeCertificateInput, opt ...request.Option) (*acm.DescribeCertificateOutput, error) {
	return &acm.DescribeCertificateOutput{
		Certificate: &acm.CertificateDetail{
			DomainValidationOptions: []*acm.DomainValidation{
				{
					ValidationMethod: aws.String(acm.ValidationMethodDns),
					ResourceRecord: &acm.ResourceRecord{
						Type:  aws.String(acm.RecordTypeCname),
						Name:  aws.String("loopback-cname.shogo82148.com."),
						Value: aws.String("loopback.shogo82148.com."),
					},
				},
			},
		},
	}, nil
}

func TestValidateCertificate_DNS(t *testing.T) {
	myacm := &mockACMClient{}
	ok, err := ValidateCertificate(context.Background(), myacm, "arn:aws:acm:ap-northeast-1:123456789012:certificate/00000000-0000-0000-0000-000000000000")
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Error("want ok, got not no ok")
	}
}
