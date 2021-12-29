# CAROOT

Usage:

1 - Setup caroot, giving is a directory name. func will be called in case this is a 1st time caroot dir.
```go
caroot.InitCA("caroot", func(ca string) {
	log.Printf("Initiating CA: %s", ca)
})
```

2 - Setup tlsConfig to create/reuse the right cert based on hostname request:

```go
log.Printf("Using https + self signed approach")
    tlscfg := &tls.Config{
        GetCertificate: func(info *tls.ClientHelloInfo) (*tls.Certificate, error) {
            ca := caroot.GetOrGenFromRoot(info.ServerName)
            return ca, nil
        },
    }

    server := &http.Server{
        Addr:      config.Addr,
        Handler:   http.DefaultServeMux,
        TLSConfig: tlscfg,
    }
    go func() {
        err := server.ListenAndServeTLS("", "")
        if err != nil {
            log.Printf("Finishing server: %s", err.Error())
        }
    }()
```

## Pending

 Better documentation
