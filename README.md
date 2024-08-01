# virus-scanner-service

Microservice to perform a virus scan on uploaded files.

This service listens for delta notifications about new files and scans
those for viruses.

[![Project Status: WIP – Initial development is in progress](https://www.repostatus.org/badges/latest/wip.svg)](https://www.repostatus.org/#wip)

## Getting started

Prerequisites:
- [file-service](https://github.com/mu-semtech/file-service)
- [mu-authorization](https://github.com/mu-semtech/mu-authorization)
- [delta-notifier](https://github.com/mu-semtech/delta-notifier)

### Adding the service to your stack

Add the following snippet to your `docker-compose.yml` to include this
service in your project.

```yaml
version: '3.4'

services:
  virus-scanner:
    image: redpencilio/virus-scanner-service:0.1.0
    links:
      - database:database
    environment:
      VIRUS_SCANNER_CLAMD_USER: # "root"
    volumes:
      - ./data/files:/share
      - type: volume
        source: virus-scanner-signatures
        target: /var/lib/clamav

volumes:
  virus-scanner-signatures:
```

> Note: The ClamAV authors do not recommend running `clamd` as `root` for
> safety reasons because ClamAV scans untrusted files that may be
> malware. However, the file-service currently saves its files with
> access permission for `root` only. Consider the security implications
> for your situation before uncommenting the line to let `clamd` run as
> `root`:
>
>       VIRUS_SCANNER_CLAMD_USER: "root"


Add rules to `dispatcher.ex` to dispatch requests to this service. E.g.

```elixir
  match "/virus-scanner/*path", %{ layer: :services } do
    Proxy.forward conn, path, "http://virus-scanner/"
  end
```
**TODO**: Change `match /virus-scanner` to `post /malware-analyses`
like for mu-cl-resources described further below?
Conflict on `get`: hello from virus-scanner vs mu-cl-resources

The host `virus-scanner` in the forward URL reflects the name of the
file service in the `docker-compose.yml` file.

Update the authorization configuration `config/authorization/config.ex`
to make sure the user has appropriate read/write access on the resource
type `stix:MalwareAnalysis`. E.g.

```elixir
    ...
    constraint: %ResourceConstraint{
      resource_types: [
        "http://docs.oasis-open.org/cti/ns/stix#MalwareAnalysis",
        ...
      ]
    }
    ...
```

Add delta-notifier to your stack as described in the [delta-notifier
documentation](https://github.com/mu-semtech/delta-notifier#readme).
Then configure delta-notifier to send relevant deltas to virus-scanner
by adding the following snippet to `config/delta/rules.js`:

```js
export default [
  {
    match: {
      predicate: {
        type: 'uri',
        value: 'http://www.semanticdesktop.org/ontologies/2007/01/19/nie#dataSource'
      },
    },
    callback: {
      url: 'http://virus-scanner/delta',
      method: 'POST',
    },
    options: {
      resourceFormat: 'v0.0.1',
      gracePeriod: 1000,
      ignoreFromSelf: true,
    }
  },
  // Other delta listeners
]
```

Run `docker-compose up` and the service should be reachable through the
dispatcher, for example at http://localhost/virus-scanner/ .

## How-to guides

### How to configure malware-analysis resources in mu-cl-resources

Ensure that you have a file resource configured as described in the
[file-service documentation](https://github.com/mu-semtech/file-service/blob/master/README.md#how-to-configure-file-resources-in-mu-cl-resources).

If you want to model the malware-analyses of the virus-scanner service
in the domain of your [mu-cl-resources](https://github.com/mu-semtech/mu-cl-resources)
service, add the following snippet to your resource configuration.

If you use the Lisp configuration format add the following to your
`domain.lisp`:

```lisp
(define-resource malware-analysis ()
  :class (s-prefix "stix:MalwareAnalysis")
  :properties `((:analysis-started :datetime ,(s-prefix "stix:analysis_started"))
                (:analysis-ended :datetime ,(s-prefix "stix:analysis_ended"))
                (:result :string ,(s-prefix "stix:result")))
  :has-one `((file :via ,(s-prefix "stix:sample_ref")
                   :as "sample-ref"))
  :resource-base (s-url "http://data.gift/virus-scanner/analysis/id/")
  :features `(include-uri)
  :on-path "malware-analyses")

(define-resource file ()
  ;; ...
  :has-many `((malware-analysis :via ,(s-prefix "stix:sample_ref")
                           :inverse t
                           :as "malware-analyses"))
  ;; ...
```

And configure this prefix in your `repository.lisp`:

```lisp
(add-prefix "stix" "http://docs.oasis-open.org/cti/ns/stix#")
```

If you use the JSON configuration format add the following to your `domain.json`:
**TODO**

Next, add the following rule to `./config/dispatcher/dispatcher.ex`.

```elixir
  define_accept_types [
    json: [ "application/vnd.api+json" ],
  ]

  ...

  get "/malware-analyses/*path", %{ accept: [ :json ], layer: :services } do
    Proxy.forward conn, path, "http://resource/malware-analyses/"
  end
```

Finally, restart the services to pick up the configuration changes:

```bash
docker-compose restart resource dispatcher
```

### How to upload a file using a curl command
The following assumes mu-dispatcher is running on localhost:80.

Download an EICAR test file and upload it to file-service:

```bash
curl -O https://secure.eicar.org/eicar.com.txt
curl -i -X POST -H "Content-Type: multipart/form-data" -F "file=@eicar.com.txt" http://localhost/files
```

The virus-scanner-service will receive a delta notification of the
upload, scan the file and write the results to the database.

To request a scan manually:

```bash
curl -i -X POST -H "Content-Type: application/json" -d '{"file":"http://mu.semte.ch/services/file-service/files/6543bc046ea4f3000e00000c"}' http://localhost/virus-scanner/scan
```

The virus-scanner-service will scan the file and add the new results to
the database. Earlier results for the same file are left untouched.

### How to check if a file is clean

To check if a file is clean, create a query that sorts the
malware-analyses for that file by `analysis-started`, take the most
recent one, check that `analysis-ended` is filled in with a
recent-enough date and that the `result` is strict-equal to `"benign"`.
This should prevent erroneously assuming that a file is clean in corner
cases such as when the malware-analysis is missing, the result is
missing or `unknown`, or an earlier result was `benign` but the most
recent analysis failed.

**TODO**: Example query.


## Reference
### Model

#### Ontologies and prefixes

| Prefix  | URI                                                       |
|---------|-----------------------------------------------------------|
| stix    | http://docs.oasis-open.org/cti/ns/stix#                   |
| nfo     | http://www.semanticdesktop.org/ontologies/2007/03/22/nfo# |
| nie     | http://www.semanticdesktop.org/ontologies/2007/01/19/nie# |

#### Malware analyses
##### Description

https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
https://github.com/oasis-open/tac-ontology/

##### Class
`stix:MalwareAnalysis`

##### Properties
| Name              | Predicate               | Range                | Definition                                                        |
|-------------------|-------------------------|----------------------|-------------------------------------------------------------------|
| analysis-started  | `stix:analysis_started` | `xsd:dateTime`       | Datetime of scan start                                            |
| analysis-ended    | `stix:analysis_ended`   | `xsd:dateTime`       | Datetime of scan end                                              |
| result            | `stix:result`           | `xsd:string`         | The result: `malicious`, `suspicious`, `benign` or `unknown`      |
| sample-ref        | `stix:sample_ref`       | `nfo:FileDataObject` | The file that was scanned                                         |
|**TODO**result-name| `stix:result_name`      | `xsd:string`         | Details of the result, e.g. names of detected malware             |

**TODO**: We could add `result-name`, but clamscan returns an array of
strings, because more than 1 malware may be found in a file. We could
write a JSON-string of that array to `result-name`, if that is not a
problem.

### Configuration

#### Environment variables

The following enviroment variables can be configured:

* `LOG_INCOMING_DELTA (default: "false")`: Log the delta message as
  received from the delta-notifier to the console.
* `LOG_INCOMING_SCAN_REQUESTS (default: "false")`: Log the requests
  received by endpoint `/scan`.
* `VIRUS_SCANNER_CLAMD_USER (default: "clamav")`: User to run the
  ClamAV daemon `clamd` as.
* The environment variables recognized by
  [mu-javascript-template](https://github.com/mu-semtech/mu-javascript-template/blob/v1.7.0/README.md#environment-variables).

### REST API

Notes:
- In various error cases (e.g. no physical file IRI found, file not
  found on disk, errors from clamscan), virus-scanner will create a
  malware-analysis resource for the requested file IRI with `result`
  `unknown`. Error details are logged. Those are not uncaught errors
  that would lead to a 500 Server Error response.
- Storing a malware-analysis in the database may fail with only a
  logged error (e.g. if 202 Accepted was already returned), or even
  silently (e.g. file IRI not in any graph at time of storing result).
- [How to check if a file is clean](#how-to-check-if-a-file-is-clean)
  describes how to ensure a file is clean considering such corner cases.

#### POST /delta
Accepts requests like those created by
[delta-notifier](https://github.com/mu-semtech/delta-notifier).

##### Response
###### 202 Accepted
Delta contains logical file IRI insertions that will be scanned.

The results will be logged and stored in the database.

###### 204 No Content
Delta contains no logical file IRI insertions. No results are stored.

###### 500 Server error
Uncaught error.

#### POST /scan
Scan a file. Accepts a `multipart/form-data` with a `file` parameter
containing a logical file IRI.

##### Response
###### 201 Created
The newly created malware-analysis in the response body:

```javascript
{
  "data": {
    "type": "malware-analyses",
    "id": "3a2cafd0-8f8a-11ee-a732-97ed1ab0131d",
    "attributes": {
      "uri": "http://data.gift/virus-scanner/analysis/id/3a2cafd0-8f8a-11ee-a732-97ed1ab0131d",
      "analysis-started": "2023-11-30T14:10:33.855Z",
      "analysis-ended": "2023-11-30T14:10:33.930Z",
      "result": "malicious",
      "sample-ref": "http://mu.semte.ch/services/file-service/files/65684a368d76fe0010000000"
    }
  }
}
```

In case `result` is `unknown` or `malicious`, further details can be
found in the virus-scanner log.

###### 400 Bad Request
`file` not a non-empty String

###### 422 Unprocessable Entity
`file` is a physical file IRI, should be a logical file IRI.

###### 500 Server error
Uncaught error.

## Development

For a more detailed look in how to develop a microservice based on the
[mu-javascript-template](https://github.com/mu-semtech/mu-javascript-template),
we would recommend reading "[Developing with the
template](https://github.com/mu-semtech/mu-javascript-template#developing-with-the-template)".

### Developing in the `mu.semte.ch` stack

Paste the following snippet in your `docker-compose.override.yml`,
replacing `../virus-scanner-service/` with an absolute or relative path
pointing to your local sources:

```yaml
version: '3.4'

services:
  virus-scanner:
    ports:
      - "8893:80"
      - "9229:9229"
    environment:
      NODE_ENV: "development"
      LOG_INCOMING_DELTA: "true"
      LOG_INCOMING_SCAN_REQUESTS: "true"
    volumes:
      - ../virus-scanner-service/:/app/
```
