# CSR with Google Cloud KMS

Quick utility tool that creates a CSR cert and signs it with a private key coming from Google Cloud KMS or HSM.
The private key never leaves Google, everyone is happy. The CSR can then be used to get cert from CA.

I would've done it with `openssl`, but there is no Google Cloud KMS engine available. (Sept. 2018)


## Usage
Build the GO project
```
go mod init https://github.com/mattes/google-cloud-kms-csr
go mod tidy
go build -o csr
```
Get the key-resource-id by running the following command:
```
gcloud kms keys versions list  --key <keyname> --keyring <keyring-name> --location=<region>
```

Key Resource Id Version has the following format:
```
projects/xxx/locations/xxx/keyRings/xxx/cryptoKeys/xxx/cryptoKeyVersions/xxx
```

Generate the CSR
```
./csr -key <key-resource-id> -out my.csr --common-name MyOrg
./csr -key <key-resource-id> \
  -out my.csr \
  --common-name="*.example.com" \
  --org="Example Ltd" \
  --org-unit=Management\
  --country=US\
  --province="New York"\
  --locality="New York"\
  --email=management@example.com
```

Make sure to use an asymmetric key. The GO script currently hard codes the hasing algorithm used for your HSM key. If GCP returns an error modify the source code appropriately, build and re-run.


You can verify `my.csr` with:

```
openssl req -text -noout -verify -in my.csr
```

Google's application credentials are used for authenticating with the Google API.
If you haven't done so already, you can set the application default credentials locally with:

```
gcloud auth application-default login
```


## Docs

  * https://cloud.google.com/kms/docs/how-tos
  * https://en.wikipedia.org/wiki/Certificate_signing_request


