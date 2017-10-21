package main

import "testing"
import "sort"
import "reflect"

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
