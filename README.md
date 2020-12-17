# Burp Extender JSON API
This extension exposes parts of the burp extension API via a JSON API.

## Why?
As pentesters, we often have to inspect and modify data which is sent via HTTP and burp is a very good tool for this
purpose. However, as soon as you need other strange software for proprietary protocols, custom crypto implementations,
compression or other stuff, it gets too time consuming to build an extension within a short time period.

As an additional benefit, this API allows you to build extensions without knowing the burp extension API. You can
use any software, it just has to be able to speak JSON via HTTP. No need for Java, Jython etc!

Basically, this extensions tries to make use of the great burp features without reimplementing logic for request
modification or similar, while giving you the freedom to use any programming language you like. A sample implementation
is provided as as PoC in pure Python (not Jython!) in the folder `python`. You can start there if you want to see
how it works.

## Limitations
Building extensions with a custom UI is currently not possible. Also, not all features of burp are implemented (yet).

## Getting Started
Clone the repo.

### Build from source or use the pre-compiled version
You can build the burp extension itself from source.
```
cd burp-extension
mvn package
```
You'll find the result in `target/burp-json-api-1.0-SNAPSHOT.jar`.

Or use a pre-compiled release version.

## Activate the extension in burp
Load the extension in burp the usual way. Please keep in mind that the order matters!

[![Video: Add extension](/images/add-extension.jpg)](https://github.com/SySS-Research/burp-extender-json-api/blob/master/videos/add-extension.mp4?raw=true "Add extension")

# Use the extension API
After loading the extension, a new HTTP service is provided on localhost port 8099. The sample implementation with
python in the folder `python` will give you a good start.

## Usage
* After adding the extension in burp, an access token will be generated and logged in the extension output
* Use the API with this token

### Python Example
* Change to directory `python`
* Set up a virtual environment like you would do with any python project and install the requirements
(`python -m venv venv; ./venv/bin/activate; pip install -r requirements.txt`)
* Start an extension by using app.py and the name of the extension you want to use (check folder `python/extensions`)
```
i.e. ./app.py -auth [auth token] -extension [extension1[ extension2]]
# This will add an additional tab i.e. in the proxy and pretty print JSON/XML.
./app.py -auth 0f6dabf6-7e5a-486a-a302-d3c7ab1444dd -extension messageeditortabprettyprint
# This will also load the sample "httplisteneraddheader"
./app.py -auth 0f6dabf6-7e5a-486a-a302-d3c7ab1444dd -extension messageeditortabprettyprint httplisteneraddheader
```

There are different extensions available in `python/extensions`. Check out the code for the details.

[![Video: Use extension](/images/use-extension.jpg)](https://github.com/SySS-Research/burp-extender-json-api/blob/master/videos/use-extension.mp4?raw=true "Use extension")

## Currently supported functions
* IntruderPayloadGenerator
* IntruderPayloadProcessor
* MessageEditorTab
* ScannerInsertionPoint
* SessionHandlingAction
* ProxyListener
* HttpListener

## Data structures
As described above, the tool just uses burp to do all the work. Most data structures are basically like in the burp
extensions, just serialized (and base64 encoded). Some examples are given below.

### Request
A request may look like this:
```
'request':
    b'POST /some/url HTTP/1.1\r\nHost: test.example.org\r\nUser-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0\r\nAccept: */*\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip,
    deflate\r\nContent-Type: application/x-www-form-urlencoded; charset=UTF-8\r\nX-Requested-With: XMLHttpRequest\r\nContent-Length: 125\r\nConnection: close\r\nCookie: ASP.NET_SessionId=foobar; foo=bar\r\n\r\nparam=test&param2=1&',
```
### Response
A response may look like this:
```
'response':
    b'HTTP/1.1 200 OK\r\nDate: Thu, 08 Aug 2019 08:49:04 GMT\r\nServer: Apache\r\nCache-Control: private\r\nContent-Type: text/xml; charset=utf-8\r\nX-XSS-Protection: 1; mode=block\r\nStrict-Transport-Security: max-age=31536000; includeSubDomains\r\nContent-Length: 1700\r\nConnection: close\r\n\r\nhttp body here',
```

### AnalyzedRequest
An analyzed request may look like this:
```
'analyzedRequest': {
    'url': 'https://test.example.org:443/foobar',
    'bodyOffset': 1331,
    'method': 'POST',
    'parameters': [{
        'nameEnd': 420,
        'valueStart': 421,
        'valueEnd': 445,
        'nameStart': 403,
        'name': 'ASP.NET_SessionId',
        'value': 'nz4g5a3xhfjqm0zzmaaaw3qq',
        'type': 2},
        {'nameEnd': 499,
        'valueStart': 500,
        'valueEnd': 592,
        'nameStart': 447,
        'name': '__RequestVerificationToken_asd457fuNDYvUG1nLkFkbWlu0',
        'value': 'foo...',
        'type': 2},
    ],
    'contentType': 1,
    'headers': [
		'POST /foo/foobar HTTP/1.1',
    	'Host: test.example.org',
	    'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:68.0) Gecko/20100101 Firefox/68.0',
	    'Accept: */*',
	    'Accept-Language: en-US,en;q=0.5',
    	'Accept-Encoding: gzip,deflate',
	    'Content-Type: application/x-www-form-urlencoded; charset=UTF-8',
    	'X-Requested-With: XMLHttpRequest',
	    'Content-Length: 125',
    	'Connection: close',
	    'Cookie: ASP.NET_SessionId=nzzg5a3thfjqm0zzma01w3qq;'
	]
}
```

### AnalzyzedResponse
A analyzed response may look like this:
```
'analyzedResponse': {
    'statusCode': 200,
    'bodyOffset': 273,
    'cookies': [],
    'statedMimeType': 'XML',
    'inferredMimeType': 'XML',
    'headers': [
		'HTTP/1.1 200 OK',
	    'Date: Thu, 08 Aug 2019 08:49:04 GMT',
    	'Server: Apache',
	    'Cache-Control: private',
    	'Content-Type: text/xml; charset=utf-8',
	    'X-XSS-Protection: 1; mode=block',
    	'Strict-Transport-Security: max-age=31536000; includeSubDomains',
	    'Content-Length: 1700',
    	'Connection: close'
	]
}
```

### AnalyzedMessage
An analyzed message wraps request/response and may look like this:
```
{
'toolFlag': 0,
'request': {see Request},
'response': None,
'analyzedRequest': {see AnalyzedRequest},
'analyzedResponse': None
}
```

### InterceptedMessage
An intercepted message may look like this:
```
{'analyzedRequest': {see analyzedRequest},
 'analyzedResponse': {see analyzedRespone},
 'message': {
    'clientIpAddress': 'localhost.localdomain',
    'interceptAction': 0,
    'listenerInterface': '127.0.0.1:8080',
    'messageInfo': {
        'comment': None,
        'highlight': None,
        'host': 'test.example.org',
        'httpService': {
            'host': 'test.example.org',
            'port': 443,
            'protocol': 'https'
        },
        'port': 443,
        'protocol': 'https',
        'request': 'see Request',
        'response': 'see Response',
        'statusCode': 0,
        'url': 'https://test.example.org:443/foo/bar?param=1'},
        'messageReference': 474
    }
}
```

## Author
Torsten Lutz, SySS GmbH, 2019 - 2020

## Disclaimer
Use at your own risk.

## Acknowledgements
Thanks to @mbechler for the code review and remarks.
