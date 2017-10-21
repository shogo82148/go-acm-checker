# go-acm-checker

go-acm-checker is a simulator of ACM (Amazon Certification Manager) Automatic Domain Validation.
It checks that Automatic Domain Validation will success.


## USAGE

At first, run [aws configure](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html).
And run `go-acm-checker`.
`go-acm-checker` validates certifications which are registered in ACM,
and report whether Automatic Domain Validation will works.

```
$ go-acm-checker
2017/10/21 14:30:04 success to validate example.com(arn:aws:acm:us-east-1:1234567890:certificate/00000000-0000-0000-0000-000000000000)
```

```
$ go-acm-checker
2017/10/21 14:30:05 failed to validate example.com
2017/10/21 14:30:05 failed to validate *.example.com
2017/10/21 14:30:05 failed to validate example.com(arn:aws:acm:us-east-1:1234567890:certificate/00000000-0000-0000-0000-000000000000)
```

## SEE ALSO

- [How Domain Validation Works](http://docs.aws.amazon.com/acm/latest/userguide/how-domain-validation-works.html)