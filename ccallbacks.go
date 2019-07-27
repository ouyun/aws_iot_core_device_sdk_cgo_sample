package main

/*
#include "aws_iot_mqtt_client_interface.h"

// The gateway functions
void disconCallbackFun(AWS_IoT_Client *pClient, void *data)
{
	void disconCallbackHandler(AWS_IoT_Client*, void*);
	disconCallbackHandler(pClient, data);
}
void subCallbackFun(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
									IoT_Publish_Message_Params *params, void *pData)
{
	void subCallbackHandler(AWS_IoT_Client *, char *, uint16_t,
									IoT_Publish_Message_Params *, void *);
	subCallbackHandler(pClient, topicName, topicNameLen, params, pData);
}
*/
import "C"