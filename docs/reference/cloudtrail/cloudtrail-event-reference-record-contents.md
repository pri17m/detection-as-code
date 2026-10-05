

# CloudTrail record contents for management, data, and network activity events
<a name="cloudtrail-event-reference-record-contents"></a>

This page describes the record contents of a management, data, or network activity event.

The body of the record contains fields that help you determine the requested action as well as when and where the request was made. When the value of **Optional** is **True**, the field is only present when it applies to the service, API, or event type. An **Optional** value of **False** means that the field is either always present, or that its presence does not depend on the service, API, or event type. An example is `responseElements`, which is present in events for actions that make changes (create, update, or delete actions).

**Note**  
Fields for enriched events such as `eventContext` are only available for management events and data events. They are not available for network events.

**`eventTime`**  
The date and time the request was completed, in coordinated universal time (UTC). An event's time stamp comes from the local host that provides the service API endpoint on which the API call was made. For example, a **CreateBucket** API event that is run in the US West (Oregon) Region would get its time stamp from the time on an AWS host running the Amazon S3 endpoint, `s3.us-west-2.amazonaws.com`. In general, AWS services use Network Time Protocol (NTP) to synchronize their system clocks.  
**Since:** 1.0  
**Optional:** False

**`eventVersion`**  
The version of the log event format. The current version is 1.11.  
The `eventVersion` value is a major and minor version in the form {{major\_version}}.{{minor\_version}}. For example, you can have an `eventVersion` value of `1.10`, where `1` is the major version, and `10` is the minor version.  
CloudTrail increments the major version if a change is made to the event structure that is not backward-compatible. This includes removing a JSON field that already exists, or changing how the contents of a field are represented (for example, a date format). CloudTrail increments the minor version if a change adds new fields to the event structure. This can occur if new information is available for some or all existing events, or if new information is available only for new event types. Applications can ignore new fields to stay compatible with new minor versions of the event structure.  
If CloudTrail introduces new event types, but the structure of the event is otherwise unchanged, the event version does not change.  
To be sure that your applications can parse the event structure, we recommend that you perform an equal-to comparison on the major version number. To be sure that fields that are expected by your application exist, we also recommend performing a greater-than-or-equal-to comparison on the minor version. There are no leading zeroes in the minor version. You can interpret both {{major\_version}} and {{minor\_version}} as numbers, and perform comparison operations.  
**Since:** 1.0  
**Optional:** False

**`userIdentity`**  
Information about the IAM identity that made a request. For more information, see [CloudTrail userIdentity element](cloudtrail-event-reference-user-identity.md).   
**Since:** 1.0  
**Optional:** False

**`eventSource`**  
The service that the request was made to. This name is typically a short form of the service name without spaces plus `.amazonaws.com`. For example:  
+ CloudFormation is `cloudformation.amazonaws.com`.
+ Amazon EC2 is `ec2.amazonaws.com`.
+ Amazon Simple Workflow Service is `swf.amazonaws.com`.
This convention has some exceptions. For example, the `eventSource` for Amazon CloudWatch is `monitoring.amazonaws.com`.  
**Since:** 1.0  
**Optional:** False

**`eventName`**  
The requested action, which is one of the actions in the API for that service.  
**Since:** 1.0  
**Optional:** False

**`awsRegion`**  
The AWS Region that the request was made to, such as `us-east-2`. See [CloudTrail supported Regions](cloudtrail-supported-regions.md).  
**Since:** 1.0  
**Optional:** False

**`sourceIPAddress`**  
The IP address that the request was made from. For actions that originate from the service console, the address reported is for the underlying customer resource, not the console web server. For services in AWS, only the DNS name is displayed.  
For events originated by AWS, this field is usually `AWS Internal/{{#}}`, where `{{#}}` is a number used for internal purposes.
**Since:** 1.0  
**Optional:** False

**`userAgent`**  
The agent through which the request was made, such as the AWS Management Console, an AWS service, the AWS SDKs or the AWS CLI.  
This field has a maximum size of 1 KB; content exceeding that limit is truncated. For event data stores configured to have a maximum event size of 1 MB, the field content is only truncated if the event payload exceeds 1 MB and the maximum field size is exceeded.  
The following are example values:  
+ `lambda.amazonaws.com` – The request was made with AWS Lambda.
+ `aws-sdk-java` – The request was made with the AWS SDK for Java. 
+ `aws-sdk-ruby` – The request was made with the AWS SDK for Ruby. 
+ `aws-cli/1.3.23 Python/2.7.6 Linux/2.6.18-164.el5` – The request was made with the AWS CLI installed on Linux. 
For events originated by AWS, if CloudTrail knows which AWS service made the call, this field is the event source of the calling service (for example, `ec2.amazonaws.com`). Otherwise, this field is `AWS Internal/{{#}}`, where `{{#}}` is a number used for internal purposes.
**Since:** 1.0  
**Optional:** True

**`errorCode`**  
The AWS service error if the request returns an error. For an example that shows this field, see [Error code and message log example](cloudtrail-log-file-examples.md#error-code-and-error-message).  
This field has a maximum size of 1 KB; content exceeding that limit is truncated. For event data stores configured to have a maximum event size of 1 MB, the field content is only truncated if the event payload exceeds 1 MB and the maximum field size is exceeded.  
For network activity events, when there is a VPC endpoint policy violation, the error code is `VpceAccessDenied`.  
**Since:** 1.0  
**Optional:** True

**`errorMessage`**  
If the request returns an error, the description of the error. This message includes messages for authorization failures. CloudTrail captures the message logged by the service in its exception handling. For an example, see [Error code and message log example](cloudtrail-log-file-examples.md#error-code-and-error-message).  
This field has a maximum size of 1 KB; content exceeding that limit is truncated. For event data stores configured to have a maximum event size of 1 MB, the field content is only truncated if the event payload exceeds 1 MB and the maximum field size is exceeded.  
For network activity events, when there is a VPC endpoint policy violation, the `errorMessage` will always be the following message: `The request was denied due to a VPC endpoint policy`. For more information about access denied events for VPC endpoint policy violations, see [ Access denied error message examples](https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_access-denied.html#access-denied-error-examples) in the *IAM User Guide*. For an example network activity event showing a VPC endpoint policy violation, see [Network activity events](cloudtrail-events.md#network-event-example) in this guide.  
Some AWS services provide the `errorCode` and `errorMessage` as top-level fields in the event. Other AWS services provide error information as part of `responseElements`.
**Since:** 1.0  
**Optional:** True

**`requestParameters`**  
The parameters, if any, that were sent with the request. These parameters are documented in the API reference documentation for the appropriate AWS service. This field has a maximum size of 100 KB. When the field size exceeds 100 KB, the `requestParameters` content is omitted. For event data stores configured to have a maximum event size of 1 MB, the field content is only omitted if the event payload exceeds 1 MB and the maximum field size is exceeded.  
**Since:** 1.0  
**Optional:** False

**`responseElements`**  
The response elements, if any, for actions that make changes (create, update, or delete actions). For `readOnly` APIs, this field is `null`. If the action  doesn't return response elements, this field is `null`. The response elements for actions are documented in the API reference  documentation for the appropriate AWS service.  
This field has a maximum size of 100 KB. When the field size exceeds 100 KB, the `reponseElements` content is omitted. For event data stores configured to have a maximum event size of 1 MB, the field content is only omitted if the event payload exceeds 1 MB and the maximum field size is exceeded.  
The `responseElements` value is useful to help you trace a request  with AWS Support. Both `x-amz-request-id` and `x-amz-id-2`  contain information that helps you trace a request with Support. These values are  the same as those that the service returns in the response to the request that  initiates the events, so you can use them to match the event to the  request.  
**Since:** 1.0  
**Optional:** False

 **`additionalEventData`**   
Additional data about the event that was not part of the request or response. This field has a maximum size of 28 KB. When the field size exceeds 28 KB, the `additionalEventData` content is omitted. For event data stores configured to have a maximum event size of 1 MB, the field content is only omitted if the event payload exceeds 1 MB and the maximum field size is exceeded.  
The content of `additionalEventData` is variable. For example, for [AWS Management Console sign-in events](cloudtrail-event-reference-aws-console-sign-in-events.md), `additionalEventData` could include the `MFAUsed` field with a value of `Yes` if the request was made by a root or IAM user using multi-factor authentication (MFA).  
**Since:** 1.0  
**Optional:** True

**`requestID`**  
The value that identifies the request. The service being called generates this value. This field has a maximum size of 1 KB; content exceeding that limit is truncated. For event data stores configured to have a maximum event size of 1 MB, the field content is only truncated if the event payload exceeds 1 MB and the maximum field size is exceeded.  
**Since:** 1.01  
**Optional:** True

**`eventID`**  
GUID generated by CloudTrail to uniquely identify each event. You can use this value to identify a single event. For example, you can use the ID as a primary key to retrieve log data from a searchable database.   
**Since:** 1.01  
**Optional:** False

**`eventType`**  
Identifies the type of event that generated the event record. This can be the one of the following values:  
+ `AwsApiCall` – An API was called.
+ `AwsServiceEvent` – The service generated an event related to your trail. For example, this can occur when another account made a call with a resource that you own. 
+ `AwsConsoleAction` – An action was taken in the console that was not an API call.
+ `AwsConsoleSignIn` – A user in your account (root, IAM, federated, SAML, or SwitchRole) signed in to the AWS Management Console.
+  `AwsVpceEvents` – CloudTrail network activity events enable VPC endpoint owners to record AWS API calls made using their VPC endpoints from a private VPC to the AWS service. To record network activity events, the VPC endpoint owner must enable network activity events for the event source. 
**Since:** 1.02  
**Optional:** False

**`apiVersion`**  
Identifies the API version associated with the `AwsApiCall` `eventType` value.  
**Since:** 1.01  
**Optional:** True

**`managementEvent`**  
A Boolean value that identifies whether the event is a management event. `managementEvent` is shown in an event record if `eventVersion` is 1.06 or higher, and the event type is one of the following:  
+ `AwsApiCall`
+ `AwsConsoleAction`
+ `AwsConsoleSignIn`
+ `AwsServiceEvent`
**Since:** 1.06  
**Optional:** True

 **`readOnly`**   
Identifies whether this operation is a read-only operation. This can be one of the following values:  
+ `true` – The operation is read-only (for example, `DescribeTrails`).
+ `false` – The operation is write-only (for example, `DeleteTrail`).
**Since:** 1.01  
**Optional:** True

 **`resources`**   
A list of resources accessed in the event. The field can contain the following information:  
+ Resource ARNs
+ Account ID of the resource owner
+ Resource type identifier in the format: `AWS::{{aws-service-name}}::{{data-type-name}}`
For example, when an `AssumeRole` event is logged, the `resources` field can appear like the following:  
+ ARN: `arn:aws:iam::123456789012:role/{{myRole}}`
+ Account ID: `123456789012`
+ Resource type identifier: `AWS::IAM::Role`
For example logs with the `resources` field, see [AWS STS API Event in CloudTrail Log File](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html#stscloudtrailexample) in the *IAM User Guide* or [ Logging AWS KMS API Calls](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html) in the *AWS Key Management Service Developer Guide*.  
**Since:** 1.01  
**Optional:** True

**`recipientAccountId`**  
Represents the account ID that received this event. The `recipientAccountID` may be different from the [CloudTrail userIdentity element](cloudtrail-event-reference-user-identity.md) `accountId`. This can occur in cross-account resource access. For example, if a KMS key, also known as an [AWS KMS key](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html), was used by a separate account to call the [Encrypt API](https://docs.aws.amazon.com/kms/latest/developerguide/ct-encrypt.html), the `accountId` and `recipientAccountID` values will be the same for the event delivered to the account that made the call, but the values will be different for the event that is delivered to the account that owns the KMS key.  
**Since:** 1.02  
**Optional:** True

**`serviceEventDetails`**  
Identifies the service event, including what triggered the event and the result. For more information, see [AWS service events](non-api-aws-service-events.md). This field has a maximum size of 100 KB. When the field size exceeds 100 KB, the `serviceEventDetails` content is omitted. For event data stores configured to have a maximum event size of 1 MB, the field content is only omitted if the event payload exceeds 1 MB and the maximum field size is exceeded.  
**Since:** 1.05  
**Optional:** True

**`sharedEventID`**  
GUID generated by CloudTrail to uniquely identify CloudTrail events from the same AWS action that is sent to different AWS accounts.  
For example, when an account uses an [AWS KMS key](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html) that belongs to another account, the account that used the KMS key and the account that owns the KMS key receive separate CloudTrail events for the same action. Each CloudTrail event delivered for this AWS action shares the same `sharedEventID`, but also has a unique `eventID` and `recipientAccountID`.  
For more information, see [Example sharedEventID](#shared-event-ID).  
The `sharedEventID` field is present only when CloudTrail events are delivered to multiple accounts. If the caller and owner are the same AWS account, CloudTrail sends only one event, and the `sharedEventID` field is not present.
**Since:** 1.03  
**Optional:** True

 **`vpcEndpointId`**   
Identifies the VPC endpoint in which requests were made from a VPC to another AWS service, such as Amazon EC2.   
For events originated by AWS and through an AWS service's VPC, this field is usually `AWS Internal` or the service name.
**Since:** 1.04  
**Optional:** True

 **`vpcEndpointAccountId`**   
Identifies the AWS account ID of the VPC endpoint owner for the corresponding endpoint for which a request has traversed.  
For events originated by AWS and through an AWS service's VPC, this field is usually `AWS Internal` or the service name.
**Since:** 1.09  
**Optional:** True

**`eventCategory`**  
Shows the event category. The event category is used in [`LookupEvents`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_LookupEvents.html) calls to filter on management events.  
+ For management events, the value is `Management`.
+ For data events, the value is `Data`.
+ For network activity events, the value is `NetworkActivity`.
**Since:** 1.07  
**Optional:** False

**`addendum`**  
If an event delivery was delayed, or additional information about an existing event becomes available after the event is logged, an addendum field shows information about why the event was delayed. If information was missing from an existing event, the addendum field includes the missing information and a reason for why it was missing. Contents include the following.  
+ **`reason`** - The reason that the event or some of its contents were missing. Values can be any of the following.
  + **`DELIVERY_DELAY`** – There was a delay delivering events. This could be caused by high network traffic, connectivity issues, or a CloudTrail service issue.
  + **`UPDATED_DATA`** – A field in the event record was missing or had an incorrect value.
  + **`SERVICE_OUTAGE`** – A service that logs events to CloudTrail had an outage, and couldn’t log events to CloudTrail. This is exceptionally rare.
+ **`updatedFields`** - The event record fields that are updated by the addendum. This is only provided if the reason is `UPDATED_DATA`.
+ **`originalRequestID`** - The original unique ID of the request. This is only provided if the reason is `UPDATED_DATA`.
+ **`originalEventID`** - The original event ID. This is only provided if the reason is `UPDATED_DATA`.
**Since:** 1.08  
**Optional:** True

**`sessionCredentialFromConsole`**  
String with a value of `true` or `false` that shows whether or not an event originated from an AWS Management Console session. This field is not shown unless the value is `true`, meaning that the client that was used to make the API call was either a proxy or an external client. If a proxy client was used, the`tlsDetails` event field is not shown.  
**Since:** 1.08  
**Optional:** True

**`eventContext`**  
This field is present in enriched events recorded for event data stores that were configured to include resource tag keys or IAM global condition keys. For more information, see [Enrich CloudTrail events by adding resource tag keys and IAM global condition keys](cloudtrail-context-events.md).  
Contents include the following:  
+ `requestContext` – Includes information about the IAM global condition keys that were evaluated during the authorization process, including additional details about the principal, session, network, and the request itself.
+ `tagContext` – Includes the tags associated with the resources that were involved in the API call as well as tags associated with IAM principals such as roles or users. For more information, see [Controlling access for IAM principals](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_iam-tags.html#access_iam-tags_control-principals). 

  API events related to deleted resources will not have resource tags.
The `eventContext` field is only present in events for event data stores that are configured to include resource tag keys and IAM global condition keys. Events delivered to **Event history**, Amazon EventBridge, viewable with the AWS CLI `lookup-events` command, and delivered to trails, will not include the `eventContext` field.
**Since:** 1.11  
**Optional:** True

**`edgeDeviceDetails`**  
Shows information about edge devices that are targets of a request. Currently, [`S3 Outposts`](https://aws.amazon.com/s3/outposts/) device events include this field. This field has a maximum size of 28 KB; content exceeding that limit is truncated. For event data stores configured to have a maximum event size of 1 MB, the field content is only truncated if the event payload exceeds 1 MB and the maximum field size is exceeded.  
**Since:** 1.08  
**Optional:** True

**`tlsDetails`**  
Shows information about the Transport Layer Security (TLS) version, cipher suites, and the fully qualified domain name (FQDN) of the client-provided host name used in the service API call, which is typically the FQDN of the service endpoint. CloudTrail still logs partial TLS details if expected information is missing or empty. For example, if the TLS version and cipher suite are present, but the `HOST` header is empty, available TLS details are still logged in the CloudTrail event.  
+ **`tlsVersion`** - The TLS version of a request.
+ **`cipherSuite`** - The cipher suite (combination of security algorithms used) of a request.
+ **`clientProvidedHostHeader`** - The client-provided host name used in the service API call, which is typically the FQDN of the service endpoint.
+ **`keyExchange`** - The key exchange method used in the TLS handshake. This field indicates whether the connection used classical cryptography or post-quantum cryptography. Example values include `X25519MLKEM768` for post-quantum TLS 1.3, `x25519` for classical TLS 1.3, and `secp256r1` for TLS 1.2.
There are some cases when the `tlsDetails` field is not present in an event record.  
+ The `tlsDetails` field is not present if the API call was made by an AWS service on your behalf. The `invokedBy` field in the `userIdentity` element identifies the AWS service that made the API call.
+ If `sessionCredentialFromConsole` is present with a value of true, `tlsDetails` is present in an event record only if an external client was used to make the API call.
**Since:** 1.08  
**Optional:** True

## Field truncation order for maximum event size of 1 MB
<a name="context-event-truncation-order"></a>

You can expand the maximum event size from 256 KB up to 1 MB when you create or update an event data store using the [CloudTrail console](query-event-data-store-cloudtrail.md), [AWS CLI](lake-cli-manage-eds.md#lake-cli-put-event-configuration), and SDKs.

Expanding the event size is helpful for analyzing and troubleshooting events because it allows you to see the full contents of fields that would normally get truncated or omitted.

When the event payload exceeds 1 MB, CloudTrail truncates fields in the following order:
+ `annotation`
+ `requestID`
+ `additionalEventData`
+ `serviceEventDetails`
+ `userAgent`
+ `errorCode`
+ `eventContext`
+ `responseElements`
+ `requestParameters`
+ `errorMessage`

If an event payload cannot be reduced to under 1 MB even after truncation, an error will occur.

## Example sharedEventID
<a name="shared-event-ID"></a>

The following is an example that describes how CloudTrail delivers two events for the same action:

1. Alice has AWS account (111111111111) and creates an AWS KMS key. She is the owner of this KMS key. 

1. Bob has AWS account (222222222222). Alice gives Bob permission to use the KMS key. 

1. Each account has a trail and a separate bucket.

1. Bob uses the KMS key to call the `Encrypt` API. 

1. CloudTrail sends two separate events. 
   + One event is sent to Bob. The event shows that he used the KMS key.
   + One event is sent to Alice. The event shows that Bob used the KMS key.
   + The events have the same `sharedEventID`, but the `eventID` and `recipientAccountID` are unique.

![How the sharedEventID field appears in logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/images/event-reference-sharedEventId.png)
