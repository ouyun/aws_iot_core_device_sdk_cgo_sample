# aws_iot_core_device_sdk_cgo_sample
This is a sample routine developed by golang following aws official device sdk sample for embedded c. I had searched everywhere for an official native golang sample to communicate with aws iot core message broker service using mqtt protocal, but nothing was able to find. There are only eight kinds of languages for device sdk provided by aws official:
* embedded c
* c++
* java
* javascript
* ios
* android
* python
* ardius yun

So, I decided to write one using cgo to interact with its wrapped c library in order to validate mqtt communication such as pub/sub over aws services.

To make this go program work, you should do the following two things:
1. Put your own credentials into ./certs folder
2. Modify configuration info in const section in main.go to reflect your certificates
