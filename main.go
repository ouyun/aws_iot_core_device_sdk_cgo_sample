// test for immigrating aws iot core device sdk sample programmed in embedded c to golang
package main

/*
#cgo CFLAGS: -I./inc -I./inc/mbedtls -I./inc/awsiotsdk -I./inc/jsmn -I./inc/platform
#cgo LDFLAGS: -L./lib -lawsiotsdk ./lib/libmbedtls.a ./lib/libmbedx509.a ./lib/libmbedcrypto.a

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#include <string.h>
#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"

bool aws_iot_is_autoreconnect_enabled(AWS_IoT_Client *pClient);
IoT_Error_t aws_iot_mqtt_attempt_reconnect(AWS_IoT_Client *pClient);
IoT_Error_t aws_iot_mqtt_init(AWS_IoT_Client *pClient, IoT_Client_Init_Params *pInitParams);
IoT_Error_t aws_iot_mqtt_connect(AWS_IoT_Client *pClient, IoT_Client_Connect_Params *pConnectParams);
IoT_Error_t aws_iot_mqtt_autoreconnect_set_status(AWS_IoT_Client *pClient, bool newStatus);
IoT_Error_t aws_iot_mqtt_subscribe(AWS_IoT_Client *pClient, const char *pTopicName, uint16_t topicNameLen,
								   QoS qos, pApplicationHandler_t pApplicationHandler, void *pApplicationHandlerData);
IoT_Error_t aws_iot_mqtt_yield(AWS_IoT_Client *pClient, uint32_t timeout_ms);
IoT_Error_t aws_iot_mqtt_publish(AWS_IoT_Client *pClient, const char *pTopicName, uint16_t topicNameLen,
								 IoT_Publish_Message_Params *pParams);

//allocators and releasers
static inline AWS_IoT_Client* aws2alloc_cli() { return calloc(1, sizeof(AWS_IoT_Client)); }
static inline IoT_Client_Init_Params* aws2alloc_initarg() { return calloc(1, sizeof(IoT_Client_Init_Params)); }
static inline IoT_Client_Connect_Params* aws2alloc_connarg() { return calloc(1, sizeof(IoT_Client_Connect_Params)); }
static inline IoT_Publish_Message_Params* aws2alloc_pmarg() { return calloc(1, sizeof(IoT_Publish_Message_Params)); }
static inline void aws2free_cli(AWS_IoT_Client* c) { free(c); }
static inline void aws2free_ia(IoT_Client_Init_Params* a) { free(a); }
static inline void aws2free_ca(IoT_Client_Connect_Params* a) { free(a); }
static inline void aws2free_pa(IoT_Publish_Message_Params* a) { free(a); }

void disconCallbackFun(AWS_IoT_Client *pClient, void *data);	//forward declaration
void subCallbackFun(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData);	//forward declaration

*/
import "C"
import (
	"bytes"
	"fmt"
	"os"
	"strings"
	//	"strconv"
	"unsafe"
)

const (
	certDirectory string = "certs"

	PathMax uint8 = 255
	AwsIotMqttHost     string = "a1o7zgrg40u2ug-ats.iot.us-east-2.amazonaws.com" ///< Customer specific MQTT HOST. The same will be used for Thing Shadow
	AwsIotMqttPort     uint16 = 443                                              ///< default port for MQTT/S
	AwsIotMqttClientId        = "OyFirstThing"                                   ///< MQTT client ID should be unique for every device
	AwsIotRootCaFilename      string = "rootCA.crt"                     ///< Root CA file name
	AwsIotCertificateFilename string = "188bbff636-certificate.pem.crt" ///< device signed certificate file name
	AwsIotPrivateKeyFilename  string = "188bbff636-private.pem.key"     ///< Device private key filename
)

var publishCount uint32 = 0

//export subCallbackHandler
func subCallbackHandler(pClient *C.AWS_IoT_Client, topicName *C.char, topicNameLen C.uint16_t, params *C.IoT_Publish_Message_Params, pData unsafe.Pointer) {
	fmt.Println("Subscribe callback at immi of cgo solution under Ubuntu vm on Mac")
	fmt.Printf("topicname[%s] topicnamelen[%d]:\tpayload[%s]\n", C.GoString(topicName)[:topicNameLen], topicNameLen, C.GoString((*C.char)(params.payload)))
}

//export disconCallbackHandler
func disconCallbackHandler(pClient *C.AWS_IoT_Client, data unsafe.Pointer) {
	fmt.Println("MQTT Disconnect")
	var rc C.IoT_Error_t = C.FAILURE

	if C.NULL == unsafe.Pointer(pClient) {
		return
	}

	fmt.Println("disconnect info:[%v]", data)

	if C.aws_iot_is_autoreconnect_enabled(pClient) {
		fmt.Println("Auto Reconnect is enabled, Reconnecting attempt will start now")
	} else {
		fmt.Println("Auto Reconnect not enabled. Starting manual reconnect...")
		rc = C.aws_iot_mqtt_attempt_reconnect(pClient)
		if C.NETWORK_RECONNECTED == rc {
			fmt.Println("Manual Reconnect Successful")
		} else {
			fmt.Printf("Manual Reconnect Failed - %d\n", rc)
		}
	}
}

type aMqtt struct {
	awsCli *C.AWS_IoT_Client
	initPara *C.IoT_Client_Init_Params
	connPara *C.IoT_Client_Connect_Params
	pubmsgParm0 *C.IoT_Publish_Message_Params
	pubmsgParm1 *C.IoT_Publish_Message_Params
}

func newAMqtt() aMqtt {
	m := &aMqtt {awsCli : C.aws2alloc_cli(), initPara : C.aws2alloc_initarg(), connPara : C.aws2alloc_connarg(), pubmsgParm0 : C.aws2alloc_pmarg(), pubmsgParm1 : C.aws2alloc_pmarg()}
	*(m.initPara) = C.iotClientInitParamsDefault
	*(m.connPara) = C.iotClientConnectParamsDefault
	return *m
}

func main() {
	infinitePublishFlag := true

	mqtt := newAMqtt()
	defer func() {
		C.aws2free_cli(mqtt.awsCli)
		C.aws2free_ia(mqtt.initPara)
		C.aws2free_ca(mqtt.connPara)
		C.aws2free_pa(mqtt.pubmsgParm0)
		C.aws2free_pa(mqtt.pubmsgParm1)
		mqtt.awsCli = nil
		mqtt.initPara = nil
		mqtt.connPara = nil
		mqtt.pubmsgParm0 = nil
		mqtt.pubmsgParm1 = nil
	}()

	var i int32 = 0

	var rc C.IoT_Error_t = C.FAILURE

	var paramsQOS0 C.IoT_Publish_Message_Params
	var paramsQOS1 C.IoT_Publish_Message_Params

	fmt.Printf("AWS IoT SDK Version %d.%d.%d-%s\n", C.VERSION_MAJOR, C.VERSION_MINOR, C.VERSION_PATCH, C.VERSION_TAG)

	currentDir, err := os.Executable()
	if err != nil {
		panic("Get current dir failed.")
	}
	idx := strings.LastIndex(currentDir, "/")
	path := currentDir[:idx]

	rootCA := path + "/" + certDirectory + "/" + AwsIotRootCaFilename
	clientCRT := path + "/" + certDirectory + "/" + AwsIotCertificateFilename
	clientKey := path + "/" + certDirectory + "/" + AwsIotPrivateKeyFilename

	fmt.Printf("rootCA\t%s\n", rootCA)
	fmt.Printf("clientCRT\t%s\n", clientCRT)
	fmt.Printf("clientKey\t%s\n", clientKey)

	mqtt.initPara.enableAutoReconnect = C.bool(false) // We enable this later below
	mqtt.initPara.pHostURL = C.CString(AwsIotMqttHost)
	mqtt.initPara.port = C.uint16_t(AwsIotMqttPort)
	mqtt.initPara.pRootCALocation = C.CString(rootCA)
	mqtt.initPara.pDeviceCertLocation = C.CString(clientCRT)
	mqtt.initPara.pDevicePrivateKeyLocation = C.CString(clientKey)
	mqtt.initPara.mqttCommandTimeout_ms = C.uint32_t(20000)
	mqtt.initPara.tlsHandshakeTimeout_ms = C.uint32_t(5000)
	mqtt.initPara.isSSLHostnameVerify = C.bool(true)
	mqtt.initPara.disconnectHandler = (C.iot_disconnect_handler)(unsafe.Pointer(C.disconCallbackFun))
	mqtt.initPara.disconnectHandlerData = C.NULL

	rc = C.aws_iot_mqtt_init(mqtt.awsCli, mqtt.initPara)
	if C.SUCCESS != rc {
		fmt.Printf("aws_iot_mqtt_init returned error : %d \n", rc)
		return
	}

	mqtt.connPara.keepAliveIntervalInSec = C.uint16_t(600)
	mqtt.connPara.isCleanSession = C.bool(true)
	mqtt.connPara.MQTTVersion = C.MQTT_3_1_1
	mqtt.connPara.pClientID = C.CString(AwsIotMqttClientId)
	mqtt.connPara.clientIDLen = (C.uint16_t)(C.strlen(C.CString(AwsIotMqttClientId)))
	mqtt.connPara.isWillMsgPresent = C.bool(false)

	fmt.Println("Connecting...")
	rc = C.aws_iot_mqtt_connect(mqtt.awsCli, mqtt.connPara)
	if C.SUCCESS != rc {
		fmt.Printf("Error(%d) connecting to %s:%d\n", rc, mqtt.initPara.pHostURL, mqtt.initPara.port)
		return
	}
	/*
	 * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
	 *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
	 *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
	 */
	rc = C.aws_iot_mqtt_autoreconnect_set_status(mqtt.awsCli, C.bool(true))
	if C.SUCCESS != rc {
		fmt.Printf("Unable to set Auto Reconnect to true - %d\n", rc)
		return
	}

	fmt.Println("Subscribing...")
	rc = C.aws_iot_mqtt_subscribe(mqtt.awsCli, C.CString("sdkTest/sub"), 11, C.QOS0, (C.pApplicationHandler_t)(unsafe.Pointer(C.subCallbackFun)), C.NULL)
	if C.SUCCESS != rc {
		fmt.Printf("Error subscribing : %d \n", rc)
		return
	}

	payLoad := bytes.NewBuffer(make([]byte, 30))
	fmt.Fprintf(payLoad, "%s : %d ", "hello from SDK", i)

	paramsQOS0.qos = C.QOS0
	paramsQOS0.payload = unsafe.Pointer(&payLoad.Bytes()[0])	//The C type void* is represented by Go's unsafe.Pointer.
	paramsQOS0.isRetained = C.uint8_t(0)

	paramsQOS1.qos = C.QOS1
	paramsQOS1.payload = unsafe.Pointer(&payLoad.Bytes()[0])	//The C type void* is represented by Go's unsafe.Pointer.
	paramsQOS1.isRetained = C.uint8_t(0)

	mqtt.pubmsgParm0.qos = C.QOS0
	mqtt.pubmsgParm0.payload = unsafe.Pointer(&payLoad.Bytes()[0])	//The C type void* is represented by Go's unsafe.Pointer.
	mqtt.pubmsgParm0.isRetained = C.uint8_t(0)

	mqtt.pubmsgParm1.qos = C.QOS1
	mqtt.pubmsgParm1.payload = unsafe.Pointer(&payLoad.Bytes()[0])	//The C type void* is represented by Go's unsafe.Pointer.
	mqtt.pubmsgParm1.isRetained = C.uint8_t(0)

	if publishCount != 0 {
		infinitePublishFlag = false
	}

	for (C.NETWORK_ATTEMPTING_RECONNECT == rc || C.NETWORK_RECONNECTED == rc || C.SUCCESS == rc) && (publishCount > 0 || infinitePublishFlag) {

		//Max time the yield function will wait for read messages
		rc = C.aws_iot_mqtt_yield(mqtt.awsCli, C.uint32_t(100))
		if C.NETWORK_ATTEMPTING_RECONNECT == rc {
			// If the client is attempting to reconnect we will skip the rest of the loop.
			continue
		}

		fmt.Println("-->sleep")
		C.sleep(1)
		payLoad.Reset()
		fmt.Fprintf(payLoad, "%s : %d ", "hello from SDK", i); i++
		s := string(payLoad.Bytes()[:])
		paramsQOS0.payloadLen = C.size_t(len(payLoad.Bytes()))
		mqtt.pubmsgParm0.payloadLen = C.strlen(C.CString(s))
		rc = C.aws_iot_mqtt_publish(mqtt.awsCli, C.CString("sdkTest/sub"), 11, mqtt.pubmsgParm0)
		if publishCount > 0 {
			publishCount--
		}

		payLoad.Reset()
		fmt.Fprintf(payLoad, "%s : %d ", "hello from SDK", i); i++
		s = string(payLoad.Bytes()[:])
		paramsQOS1.payloadLen = C.size_t(len(payLoad.Bytes()))
		mqtt.pubmsgParm1.payloadLen = C.strlen(C.CString(s))
		rc = C.aws_iot_mqtt_publish(mqtt.awsCli, C.CString("sdkTest/sub"), 11, mqtt.pubmsgParm1)
		if rc == C.MQTT_REQUEST_TIMEOUT_ERROR {
			fmt.Println("QOS1 publish ack not received.")
			rc = C.SUCCESS
		}
		if publishCount > 0 {
			publishCount--
		}
	}

	if C.SUCCESS != rc {
		fmt.Println("An error occurred in the loop.")
	} else {
		fmt.Println("Publish done")
	}

	return
}
