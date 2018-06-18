package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"
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
