

# Understanding CloudTrail events
<a name="cloudtrail-events"></a>

An event in CloudTrail is the record of an activity in an AWS account. This activity can be an action taken by an IAM identity, or service that is monitorable by CloudTrail. CloudTrail events provide a history of both API and non-API account activity made through the AWS Management Console, AWS SDKs, command line tools, and other AWS services.

CloudTrail log files aren't an ordered stack trace of the public API calls, so events don't appear in any specific order.

There are four types of CloudTrail events:
+ [Management events](#cloudtrail-management-events)
+ [Data events](#cloudtrail-data-events)
+ [Network activity events](#cloudtrail-network-events)
+ [Insights events](#cloudtrail-insights-events)

By default, trails and event data stores log management events, but not data events, network activity events, or Insights events.

All event types use a CloudTrail JSON log format. The log contains information about requests for resources in your account, such as who made the request, the services used, the actions performed, and parameters for the action. The event data is enclosed in a `Records` array.

For information about CloudTrail event record fields for management, data, and network activity events, see [CloudTrail record contents for management, data, and network activity events](cloudtrail-event-reference-record-contents.md).

For information about CloudTrail event record fields for Insights events for trails, see [CloudTrail record contents for Insights events for trails](cloudtrail-insights-fields-trails.md).

For information about CloudTrail event record fields for Insights events for event data stores, see [CloudTrail record contents for Insights events for event data stores](cloudtrail-insights-fields-lake.md).

## Management events
<a name="cloudtrail-management-events"></a>

Management events provide information about management operations that are performed on resources in your AWS account. These are also known as *control plane operations*.

Example management events include:
+ Configuring security (for example, AWS Identity and Access Management `AttachRolePolicy` API operations).
+ Registering devices (for example, Amazon EC2 `CreateDefaultVpc` API operations).
+ Configuring rules for routing data (for example, Amazon EC2 `CreateSubnet` API operations).
+ Setting up logging (for example, AWS CloudTrail `CreateTrail` API operations).

Management events can also include non-API events that occur in your account. For example, when a user signs in to your account, CloudTrail logs the `ConsoleLogin` event. For more information, see [Non-API events captured by CloudTrail](cloudtrail-non-api-events.md).

By default, CloudTrail trails and CloudTrail Lake event data stores log management events. For more information about logging management events, see [Logging management events](logging-management-events-with-cloudtrail.md).

The following example shows a single log record of a management event. In this event, an IAM user named `Mary_Major` ran the **aws cloudtrail start-logging** command to call the CloudTrail [`StartLogging`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartLogging.html) action to start the logging process on a trail named `myTrail`.

```
{
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "EXAMPLE6E4XEGITWATV6R",
        "arn": "arn:aws:iam::123456789012:user/Mary_Major",
        "accountId": "123456789012",
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "userName": "Mary_Major",
        "sessionContext": {
            "attributes": {
                "creationDate": "2023-07-19T21:11:57Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2023-07-19T21:33:41Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StartLogging",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "userAgent": "aws-cli/2.13.5 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/cloudtrail.start-logging",
    "requestParameters": {
        "name": "myTrail"
    },
    "responseElements": null,
    "requestID": "9d478fc1-4f10-490f-a26b-EXAMPLE0e932",
    "eventID": "eae87c48-d421-4626-94f5-EXAMPLEac994",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "123456789012",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "cloudtrail.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

In this next example, an IAM user user named `Paulo_Santos` ran the **aws cloudtrail start-event-data-store-ingestion** command to call the [`StartEventDataStoreIngestion`](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_StartEventDataStoreIngestion.html) action to start ingestion on an event data store.

```
{
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "IAMUser",
        "principalId": "EXAMPLEPHCNW5EQV7NA54",
        "arn": "arn:aws:iam::123456789012:user/Paulo_Santos",
        "accountId": "123456789012",
        "accessKeyId": "(AKIAIOSFODNN7EXAMPLE",
        "userName": "Paulo_Santos",
        "sessionContext": {
            "attributes": {
                "creationDate": "2023-07-21T21:55:30Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2023-07-21T21:57:28Z",
    "eventSource": "cloudtrail.amazonaws.com",
    "eventName": "StartEventDataStoreIngestion",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "userAgent": "aws-cli/2.13.1 Python/3.11.4 Linux/4.14.255-314-253.539.amzn2.x86_64 exec-env/CloudShell exe/x86_64.amzn.2 prompt/off command/cloudtrail.start-event-data-store-ingestion",
    "requestParameters": {
        "eventDataStore": "arn:aws:cloudtrail:us-east-1:123456789012:eventdatastore/2a8f2138-0caa-46c8-a194-EXAMPLE87d41"
    },
    "responseElements": null,
    "requestID": "f62a3494-ba4e-49ee-8e27-EXAMPLE4253f",
    "eventID": "d97ca7e2-04fe-45b4-882d-EXAMPLEa9b2c",
    "readOnly": false,
    "eventType": "AwsApiCall",
    "managementEvent": true,
    "recipientAccountId": "123456789012",
    "eventCategory": "Management",
    "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "cloudtrail.us-east-1.amazonaws.com"
    },
    "sessionCredentialFromConsole": "true"
}
```

## Data events
<a name="cloudtrail-data-events"></a>

Data events provide information about the resource operations performed on or in a resource. These are also known as *data plane operations*. Data events are often high-volume activities.

Example data events include:
+ [Amazon S3 object-level API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events) (for example, `GetObject`, `DeleteObject`, and `PutObject` API operations) on objects in S3 buckets.
+ AWS Lambda function execution activity (the `Invoke` API).
+ CloudTrail [`PutAuditEvents`](https://docs.aws.amazon.com/awscloudtraildata/latest/APIReference/API_PutAuditEvents.html) activity on a [CloudTrail Lake channel](query-event-data-store-integration.md) that is used to log events from outside AWS.
+ Amazon SNS [`Publish`](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html) and [`PublishBatch`](https://docs.aws.amazon.com/sns/latest/api/API_PublishBatch.html) API operations on topics.

The following table shows the resource types available for trails and event data stores. The **Resource type (console)** column shows the appropriate selection in the console. The **resources.type value** column shows the `resources.type` value that you would specify to include data events of that type in your trail or event data store using the AWS CLI or CloudTrail APIs.

For trails, you can use basic or advanced event selectors to log data events for Amazon S3 objects in general purpose buckets, Lambda functions, and DynamoDB tables (shown in the first three rows of the table). You can use only advanced event selectors to log the resource types shown in the remaining rows.

For event data stores, you can use only advanced event selectors to include data events.

### Data events supported by AWS CloudTrail
<a name="w2aac21c23c17"></a>



| AWS service | Description | Resource type (console) | resources.type value | 
| --- | --- | --- | --- | 
| Amazon RDS | [Amazon RDS API activity](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html#logging-using-cloudtrail-data-api.including-excluding-cloudtrail-events) on a DB Cluster. | RDS Data API - DB Cluster | AWS::RDS::DBCluster | 
| Amazon S3 | [Amazon S3 object-level API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events) (for example, `GetObject`, `DeleteObject`, and `PutObject` API operations) on objects in general purpose buckets. | S3 | AWS::S3::Object | 
| Amazon S3 | [Amazon S3 API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events) on access points. | S3 Access Point | AWS::S3::AccessPoint | 
| Amazon S3 | [Amazon S3 object-level API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events) (for example, `GetObject`, `DeleteObject`, and `PutObject` API operations) on objects in directory buckets. | S3 Express | AWS::S3Express::Object | 
| Amazon S3 | [Amazon S3 Object Lambda access points API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events), such as calls to `CompleteMultipartUpload` and `GetObject`. | S3 Object Lambda | AWS::S3ObjectLambda::AccessPoint | 
| Amazon S3 | Amazon FSx API activity on volumes.  | FSx Volume | AWS::FSx::Volume | 
| Amazon S3 Tables | Amazon S3 API activity on [tables](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-tables-create.html). | S3 table | AWS::S3Tables::Table | 
| Amazon S3 Tables | Amazon S3 API activity on [table buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-tables-buckets.html). | S3 table bucket | AWS::S3Tables::TableBucket | 
| Amazon S3 Vectors | Amazon S3 API activity on [vector buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-vectors-buckets.html). | S3 vector bucket | AWS::S3Vectors::VectorBucket | 
| Amazon S3 Vectors | Amazon S3 API activity on [vector indexes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-vectors-indexes.html). | S3 vector index | AWS::S3Vectors::Index | 
| Amazon S3 on Outposts | [Amazon S3 on Outposts object-level API activity](https://docs.aws.amazon.com/AmazonS3/latest/userguide/cloudtrail-logging-s3-info.html#cloudtrail-data-events). | S3 Outposts | AWS::S3Outposts::Object | 
| Amazon SNS | Amazon SNS [`Publish`](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html) API operations on platform endpoints. | SNS platform endpoint | AWS::SNS::PlatformEndpoint | 
| Amazon SNS | Amazon SNS [`Publish`](https://docs.aws.amazon.com/sns/latest/api/API_Publish.html) and [`PublishBatch`](https://docs.aws.amazon.com/sns/latest/api/API_PublishBatch.html) API operations on topics. | SNS topic | AWS::SNS::Topic | 
| Amazon SQS | [Amazon SQS API activity](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-logging-using-cloudtrail.html#sqs-data-events-in-cloud-trail) on messages. | SQS | AWS::SQS::Queue | 
| Supply Chain | Supply Chain API activity on an instance. | Supply Chain | AWS::SCN::Instance | 
| Amazon SWF | [Amazon SWF API activity](https://docs.aws.amazon.com/amazonswf/latest/developerguide/ct-logging.html#cloudtrail-data-events) on [domains](https://docs.aws.amazon.com/amazonswf/latest/developerguide/swf-dev-domains.html). | SWF domain | AWS::SWF::Domain | 
| AWS AppConfig | [AWS AppConfig API activity](https://docs.aws.amazon.com/appconfig/latest/userguide/logging-using-cloudtrail.html#appconfig-data-events-cloudtrail) for configuration operations such as calls to `StartConfigurationSession` and `GetLatestConfiguration`. | AWS AppConfig | AWS::AppConfig::Configuration | 
| AWS AppSync | [AWS AppSync API activity](https://docs.aws.amazon.com/appsync/latest/devguide/cloudtrail-logging.html#cloudtrail-data-events) on AppSync GraphQL APIs. | AppSync GraphQL | AWS::AppSync::GraphQLApi | 
| Amazon Aurora DSQL | Amazon Aurora DSQL API activity on cluster resources.  | Amazon Aurora DSQL | AWS::DSQL::Cluster | 
| AWS B2B Data Interchange | B2B Data Interchange API activity for Transformer operations such as calls to `GetTransformerJob` and `StartTransformerJob`. | B2B Data Interchange | AWS::B2BI::Transformer | 
| AWS Backup | AWS Backup Search Data API activity on search jobs. | AWS Backup Search Data APIs | AWS::Backup::SearchJob | 
| Amazon Bedrock | [Amazon Bedrock API activity](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html#service-name-data-events-cloudtrail) on an agent alias. | Bedrock agent alias | AWS::Bedrock::AgentAlias | 
| Amazon Bedrock | Amazon Bedrock API activity on async invocations. | Bedrock async invoke | AWS::Bedrock::AsyncInvoke | 
| Amazon Bedrock | Amazon Bedrock API activity on a flow alias. | Bedrock flow alias | AWS::Bedrock::FlowAlias | 
| Amazon Bedrock | Amazon Bedrock API activity on guardrails. | Bedrock guardrail | AWS::Bedrock::Guardrail | 
| Amazon Bedrock | Amazon Bedrock API activity on inline agents. | Bedrock Invoke Inline-Agent | AWS::Bedrock::InlineAgent | 
| Amazon Bedrock | [Amazon Bedrock API activity](https://docs.aws.amazon.com/bedrock/latest/userguide/logging-using-cloudtrail.html#service-name-data-events-cloudtrail) on a knowledge base. | Bedrock knowledge base | AWS::Bedrock::KnowledgeBase | 
| Amazon Bedrock | Amazon Bedrock API activity on models. | Bedrock model | AWS::Bedrock::Model | 
| Amazon Bedrock | Amazon Bedrock API activity on prompts. | Bedrock prompt | AWS::Bedrock::PromptVersion | 
| Amazon Bedrock | Amazon Bedrock API activity on sessions. | Bedrock session | AWS::Bedrock::Session | 
| Amazon Bedrock | Amazon Bedrock API activity on flow executions.  | Bedrock flow execution | AWS::Bedrock::FlowExecution | 
| Amazon Bedrock | Amazon Bedrock API activity on an automated reasoning policy.  | Bedrock automated reasoning policy | AWS::Bedrock::AutomatedReasoningPolicy | 
| Amazon Bedrock | Amazon Bedrock API activity on an automated reasoning policy version.  | Bedrock automated reasoning policy version | AWS::Bedrock::AutomatedReasoningPolicyVersion | 
| Amazon Bedrock | Amazon Bedrock data automation project API activity. | **Bedrock Data Automation project** | `AWS::Bedrock::DataAutomationProject` | 
| Amazon Bedrock | Bedrock data automation invocation API activity. | **Bedrock Data Automation invocation** | `AWS::Bedrock::DataAutomationInvocation` | 
| Amazon Bedrock | Amazon Bedrock data automation profile API activity. | **Bedrock Data Automation profile** | `AWS::Bedrock::DataAutomationProfile` | 
| Amazon Bedrock | Amazon Bedrock blueprint API activity. | **Bedrock blueprint** | `AWS::Bedrock::Blueprint` | 
| Amazon Bedrock | Amazon Bedrock Code-Interpreter API activity. | **Bedrock-AgentCore Code-Interpreter** | `AWS::BedrockAgentCore::CodeInterpreter` | 
| Amazon Bedrock | Amazon Bedrock Browser API activity. | **Bedrock-AgentCore Browser** | `AWS::BedrockAgentCore::Browser` | 
| Amazon Bedrock | Amazon Bedrock Workload Identity API activity. | **Bedrock-AgentCore Workload Identity** | `AWS::BedrockAgentCore::WorkloadIdentity` | 
| Amazon Bedrock | Amazon Bedrock Workload Identity Directory API activity. | **Bedrock-AgentCore Workload Identity Directory** | `AWS::BedrockAgentCore::WorkloadIdentityDirectory` | 
| Amazon Bedrock | Amazon Bedrock Token Vault API activity. | **Bedrock-AgentCore Token Vault** | `AWS::BedrockAgentCore::TokenVault` | 
| Amazon Bedrock | Amazon Bedrock APIKey CredentialProvider API activity. | **Bedrock-AgentCore APIKey CredentialProvider** | `AWS::BedrockAgentCore::APIKeyCredentialProvider` | 
| Amazon Bedrock | Amazon Bedrock Runtime API activity. | **Bedrock-AgentCore Runtime** | `AWS::BedrockAgentCore::Runtime` | 
| Amazon Bedrock | Amazon Bedrock Runtime-Endpoint API activity. | **Bedrock-AgentCore Runtime-Endpoint** | `AWS::BedrockAgentCore::RuntimeEndpoint` | 
| Amazon Bedrock | Amazon Bedrock Gateway API activity. | **Bedrock-AgentCore Gateway** | `AWS::BedrockAgentCore::Gateway` | 
| Amazon Bedrock | Amazon Bedrock Memory API activity. | **Bedrock-AgentCore Memory** | `AWS::BedrockAgentCore::Memory` | 
| Amazon Bedrock | Amazon Bedrock Oauth2 CredentialProvider API activity. | **Bedrock-AgentCore Oauth2 CredentialProvider** | `AWS::BedrockAgentCore::OAuth2CredentialProvider` | 
| Amazon Bedrock | Amazon Bedrock Browser-Custom API activity. | **Bedrock-AgentCore Browser-Custom** | `AWS::BedrockAgentCore::BrowserCustom` | 
| Amazon Bedrock | Amazon Bedrock Code-Interpreter-Custom API activity. | **Bedrock-AgentCore Code-Interpreter-Custom** | `AWS::BedrockAgentCore::CodeInterpreterCustom` | 
| Amazon Bedrock | Amazon Bedrock Tool API activity. | Bedrock Tool | AWS::Bedrock::Tool | 
| AWS Cloud Map | [AWS Cloud Map API activity](https://docs.aws.amazon.com/cloud-map/latest/dg/cloudtrail-data-events.html) on a [namespace](https://docs.aws.amazon.com/cloud-map/latest/api/API_Namespace.html). | AWS Cloud Map namespace | AWS::ServiceDiscovery::Namespace | 
| AWS Cloud Map | [AWS Cloud Map API activity](https://docs.aws.amazon.com/cloud-map/latest/dg/cloudtrail-data-events.html) on a [service](https://docs.aws.amazon.com/cloud-map/latest/api/API_Service.html). | AWS Cloud Map service | AWS::ServiceDiscovery::Service | 
| Amazon CloudFront | CloudFront API activity on a [KeyValueStore](https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_KeyValueStore.html). | CloudFront KeyValueStore | AWS::CloudFront::KeyValueStore | 
| AWS CloudTrail | CloudTrail [`PutAuditEvents`](https://docs.aws.amazon.com/awscloudtraildata/latest/APIReference/API_PutAuditEvents.html) activity on a [CloudTrail Lake channel](query-event-data-store-integration.md) that is used to log events from outside AWS. | CloudTrail channel | AWS::CloudTrail::Channel | 
| Amazon CloudWatch | [Amazon CloudWatch API activity](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html#CloudWatch-data-plane-events) on metrics. | CloudWatch metric | AWS::CloudWatch::Metric | 
| Amazon CloudWatch Network Flow Monitor | Amazon CloudWatch Network Flow Monitor API activity on monitors. | Network Flow Monitor monitor | AWS::NetworkFlowMonitor::Monitor | 
| Amazon CloudWatch Network Flow Monitor | Amazon CloudWatch Network Flow Monitor API activity on scopes. | Network Flow Monitor scope | AWS::NetworkFlowMonitor::Scope | 
| Amazon CloudWatch RUM | Amazon CloudWatch RUM API activity on app monitors. | RUM app monitor | AWS::RUM::AppMonitor | 
| Amazon CodeGuru Profiler | CodeGuru Profiler API activity on profiling groups. | CodeGuru Profiler profiling group | AWS::CodeGuruProfiler::ProfilingGroup | 
| Amazon CodeWhisperer | Amazon CodeWhisperer API activity on a customization. | CodeWhisperer customization | AWS::CodeWhisperer::Customization | 
| Amazon CodeWhisperer | Amazon CodeWhisperer API activity on a profile. | CodeWhisperer | AWS::CodeWhisperer::Profile | 
| Amazon Cognito | Amazon Cognito API activity on Amazon Cognito [identity pools](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-info-in-cloudtrail.html#identity-pools-cloudtrail-events). | Cognito Identity Pools | AWS::Cognito::IdentityPool | 
| AWS Data Exchange | AWS Data Exchange API activity on assets. | **Data Exchange asset** | `AWS::DataExchange::Asset` | 
| Amazon Data Firehose | Amazon Data Firehose delivery stream API activity. | **Amazon Data Firehose** | `AWS::KinesisFirehose::DeliveryStream` | 
| AWS Deadline Cloud | [Deadline Cloud](https://docs.aws.amazon.com/deadline-cloud/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on fleets. | **Deadline Cloud fleet** | `AWS::Deadline::Fleet` | 
| AWS Deadline Cloud | [Deadline Cloud](https://docs.aws.amazon.com/deadline-cloud/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on jobs. | **Deadline Cloud job** | `AWS::Deadline::Job` | 
| AWS Deadline Cloud | [Deadline Cloud](https://docs.aws.amazon.com/deadline-cloud/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on queues. | **Deadline Cloud queue** | `AWS::Deadline::Queue` | 
| AWS Deadline Cloud | [Deadline Cloud](https://docs.aws.amazon.com/deadline-cloud/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on workers. | **Deadline Cloud worker** | `AWS::Deadline::Worker` | 
| Amazon DynamoDB | [Amazon DynamoDB item-level API activity](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html#ddb-data-plane-events-in-cloudtrail) on tables (for example, `PutItem`, `DeleteItem`, and `UpdateItem` API operations).For tables with streams enabled, the `resources` field in the data event contains both `AWS::DynamoDB::Stream` and `AWS::DynamoDB::Table`. If you specify `AWS::DynamoDB::Table` for the `resources.type`, it will log both DynamoDB table and DynamoDB streams events by default. To exclude [streams events](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html#ddb-data-plane-events-in-cloudtrail), add a filter on the `eventName` field.  | DynamoDB | `AWS::DynamoDB::Table` | 
| Amazon DynamoDB | [Amazon DynamoDB](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/logging-using-cloudtrail.html#ddb-data-plane-events-in-cloudtrail) API activity on streams. | DynamoDB Streams | AWS::DynamoDB::Stream | 
| Amazon Elastic Block Store | [Amazon Elastic Block Store (EBS)](https://docs.aws.amazon.com/ebs/latest/userguide/logging-ebs-apis-using-cloudtrail.html) direct APIs, such as `PutSnapshotBlock`, `GetSnapshotBlock`, and `ListChangedBlocks` on Amazon EBS snapshots. | Amazon EBS direct APIs | AWS::EC2::Snapshot | 
| Amazon Elastic Compute Cloud | Amazon EC2 instance connect endpoint API activity. | **EC2 instance connect endpoint** | `AWS::EC2::InstanceConnectEndpoint` | 
| Amazon Elastic Container Service | Amazon Elastic Container Service API activity on a container instance. | ECS container instance | AWS::ECS::ContainerInstance | 
| Amazon Elastic Kubernetes Service | Amazon Elastic Kubernetes Service API activity on dashboards.  | Amazon Elastic Kubernetes Service dashboard | AWS::EKS::Dashboard | 
| Amazon EMR | [Amazon EMR API activity](https://docs.aws.amazon.com/emr/latest/ManagementGuide/logging-using-cloudtrail.html#cloudtrail-data-events) on a write-ahead log workspace. | EMR write-ahead log workspace | AWS::EMRWAL::Workspace | 
| AWS End User Messaging SMS | [AWS End User Messaging SMS](https://docs.aws.amazon.com/sms-voice/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on origination identities. | SMS Voice origination identity | AWS::SMSVoice::OriginationIdentity | 
| AWS End User Messaging SMS | [AWS End User Messaging SMS](https://docs.aws.amazon.com/sms-voice/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on messages. | SMS Voice message | AWS::SMSVoice::Message | 
| AWS End User Messaging Social | [AWS End User Messaging Social](https://docs.aws.amazon.com/social-messaging/latest/userguide/logging-using-cloudtrail.html#cloudtrail-data-events) API activity on phone number IDs. | Social-Messaging Phone Number Id | AWS::SocialMessaging::PhoneNumberId | 
| AWS End User Messaging Social | AWS End User Messaging Social API activity on Waba IDs. | Social-Messaging Waba ID | AWS::SocialMessaging::WabaId | 
| Amazon FinSpace | [Amazon FinSpace](https://docs.aws.amazon.com/finspace/latest/userguide/logging-cloudtrail-events.html#finspace-dataplane-events) API activity on environments. | FinSpace | AWS::FinSpace::Environment | 
| Amazon GameLift Streams | Amazon GameLift Streams [streaming API activity](https://docs.aws.amazon.com/gameliftstreams/latest/developerguide/logging-using-cloudtrail.html#cloudtrail-data-events) on applications. | GameLift Streams application | AWS::GameLiftStreams::Application | 
| Amazon GameLift Streams | Amazon GameLift Streams [streaming API activity](https://docs.aws.amazon.com/gameliftstreams/latest/developerguide/logging-using-cloudtrail.html#cloudtrail-data-events) on stream groups. | GameLift Streams stream group | AWS::GameLiftStreams::StreamGroup | 
| AWS Glue | AWS Glue API activity on tables that were created by Lake Formation. | Lake Formation | AWS::Glue::Table | 
| Amazon GuardDuty | Amazon GuardDuty API activity for a [detector](https://docs.aws.amazon.com/guardduty/latest/ug/logging-using-cloudtrail.html#guardduty-data-events-in-cloudtrail). | GuardDuty detector | AWS::GuardDuty::Detector | 
| AWS HealthImaging | AWS HealthImaging API activity on data stores. | MedicalImaging data store | AWS::MedicalImaging::Datastore | 
| AWS HealthImaging | AWS HealthImaging image set API activity. | **MedicalImaging image set** | `AWS::MedicalImaging::Imageset` | 
| AWS IoT | [AWS IoT API activity](https://docs.aws.amazon.com/greengrass/v2/developerguide/logging-using-cloudtrail.html#greengrass-data-events-cloudtrail) on [certificates](https://docs.aws.amazon.com/iot/latest/developerguide/x509-client-certs.html). | IoT certificate | AWS::IoT::Certificate | 
| AWS IoT | [AWS IoT API activity](https://docs.aws.amazon.com/greengrass/v2/developerguide/logging-using-cloudtrail.html#greengrass-data-events-cloudtrail) on [things](https://docs.aws.amazon.com/iot/latest/developerguide/thing-registry.html). | IoT thing | AWS::IoT::Thing | 
| AWS IoT Greengrass Version 2 | [Greengrass API activity](https://docs.aws.amazon.com/greengrass/v2/developerguide/logging-using-cloudtrail.html#greengrass-data-events-cloudtrail) from a Greengrass core device on a component version.Greengrass doesn't log access denied events. | IoT Greengrass component version | AWS::GreengrassV2::ComponentVersion | 
| AWS IoT Greengrass Version 2 | [Greengrass API activity](https://docs.aws.amazon.com/greengrass/v2/developerguide/logging-using-cloudtrail.html#greengrass-data-events-cloudtrail) from a Greengrass core device on a deployment.Greengrass doesn't log access denied events. | IoT Greengrass deployment | AWS::GreengrassV2::Deployment | 
| AWS IoT SiteWise | [IoT SiteWise API activity](https://docs.aws.amazon.com/iot-sitewise/latest/userguide/logging-using-cloudtrail.html#service-name-data-events-cloudtrail) on [assets](https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_CreateAsset.html). | IoT SiteWise asset | AWS::IoTSiteWise::Asset | 
| AWS IoT SiteWise | [IoT SiteWise API activity](https://docs.aws.amazon.com/iot-sitewise/latest/userguide/logging-using-cloudtrail.html#service-name-data-events-cloudtrail) on [time series](https://docs.aws.amazon.com/iot-sitewise/latest/APIReference/API_DescribeTimeSeries.html). | IoT SiteWise time series | AWS::IoTSiteWise::TimeSeries | 
| AWS IoT SiteWise Assistant | Sitewise Assistant API activity on conversations. | Sitewise Assistant conversation | AWS::SitewiseAssistant::Conversation | 
| AWS IoT TwinMaker | IoT TwinMaker API activity on an [entity](https://docs.aws.amazon.com/iot-twinmaker/latest/apireference/API_CreateEntity.html). | IoT TwinMaker entity | AWS::IoTTwinMaker::Entity | 
| AWS IoT TwinMaker | IoT TwinMaker API activity on a [workspace](https://docs.aws.amazon.com/iot-twinmaker/latest/apireference/API_CreateWorkspace.html). | IoT TwinMaker workspace | AWS::IoTTwinMaker::Workspace | 
| Amazon Kendra Intelligent Ranking | Amazon Kendra Intelligent Ranking API activity on [rescore execution plans](https://docs.aws.amazon.com/kendra/latest/dg/cloudtrail-intelligent-ranking.html#cloud-trail-intelligent-ranking-log-entry). | Kendra Ranking | AWS::KendraRanking::ExecutionPlan | 
| Amazon Keyspaces (for Apache Cassandra) | [Amazon Keyspaces API activity](https://docs.aws.amazon.com/keyspaces/latest/devguide/logging-using-cloudtrail.html#keyspaces-in-cloudtrail-dml) on a table. | Cassandra table | AWS::Cassandra::Table | 
| Amazon Keyspaces (for Apache Cassandra) | Amazon Keyspaces (for Apache Cassandra) API activity on Cassandra CDC streams.  | Cassandra CDC streams | AWS::Cassandra::Stream | 
| Amazon Kinesis Data Streams | Kinesis Data Streams API activity on [streams](https://docs.aws.amazon.com/streams/latest/dev/working-with-streams.html). | Kinesis stream | AWS::Kinesis::Stream | 
| Amazon Kinesis Data Streams | Kinesis Data Streams API activity on [stream consumers](https://docs.aws.amazon.com/streams/latest/dev/building-consumers.html). | Kinesis stream consumer | AWS::Kinesis::StreamConsumer | 
| Amazon Kinesis Video Streams | Kinesis Video Streams API activity on video streams, such as calls to GetMedia and PutMedia. | Kinesis video stream | AWS::KinesisVideo::Stream | 
| Amazon Kinesis Video Streams | Kinesis Video Streams video signaling channel API activity. | **Kinesis video signaling channel** | `AWS::KinesisVideo::SignalingChannel` | 
| AWS Lambda | AWS Lambda function execution activity (the `Invoke` API). | Lambda | AWS::Lambda::Function | 
| Amazon Location Maps | Amazon Location Maps API activity. | Geo Maps | AWS::GeoMaps::Provider | 
| Amazon Location Places | Amazon Location Places API activity. | Geo Places | AWS::GeoPlaces::Provider | 
| Amazon Location Routes | Amazon Location Routes API activity. | Geo Routes | AWS::GeoRoutes::Provider | 
| Amazon Machine Learning | Machine Learning API activity on ML models. | Maching Learning MlModel | AWS::MachineLearning::MlModel | 
| Amazon Managed Blockchain | Amazon Managed Blockchain API activity on a network. | Managed Blockchain network | AWS::ManagedBlockchain::Network | 
| Amazon Managed Blockchain | [Amazon Managed Blockchain](https://docs.aws.amazon.com/managed-blockchain/latest/ethereum-dev/logging-using-cloudtrail.html#ethereum-jsonrpc-logging) JSON-RPC calls on Ethereum nodes, such as `eth_getBalance` or `eth_getBlockByNumber`. | Managed Blockchain | AWS::ManagedBlockchain::Node | 
| Amazon Managed Blockchain Query | Amazon Managed Blockchain Query API activity. | Managed Blockchain Query | AWS::ManagedBlockchainQuery::QueryAPI | 
| Amazon Managed Workflows for Apache Airflow | Amazon MWAA API activity on environments. | Managed Apache Airflow | AWS::MWAA::Environment | 
| Amazon Neptune Graph | Data API activities, for example queries, algorithms, or vector search, on a Neptune Graph. | Neptune Graph | AWS::NeptuneGraph::Graph | 
| Amazon One Enterprise | Amazon One Enterprise API activity on a UKey. | Amazon One UKey | AWS::One::UKey | 
| Amazon One Enterprise | Amazon One Enterprise API activity on users. | Amazon One User | AWS::One::User | 
| AWS Payment Cryptography | AWS Payment Cryptography API activity on aliases. | Payment Cryptography Alias | AWS::PaymentCryptography::Alias | 
| AWS Payment Cryptography | AWS Payment Cryptography API activity on keys. | Payment Cryptography Key | AWS::PaymentCryptography::Key | 
| Amazon Pinpoint | Amazon Pinpoint API activity on mobile targeting applications. | Mobile Targeting Application | AWS::Pinpoint::App | 
| AWS Private CA | AWS Private CA Connector for Active Directory API activity. | AWS Private CA Connector for Active Directory | AWS::PCAConnectorAD::Connector | 
| AWS Private CA | AWS Private CA Connector for SCEP API activity. | AWS Private CA Connector for SCEP | AWS::PCAConnectorSCEP::Connector | 
| Amazon Q Apps | Data API activity on [Amazon Q Apps](https://docs.aws.amazon.com/amazonq/latest/qbusiness-ug/purpose-built-qapps.html). | Amazon Q Apps | AWS::QApps::QApp | 
| Amazon Q Apps | Data API activity on Amazon Q App sessions. | Amazon Q App Session | AWS::QApps::QAppSession | 
| Amazon Q Business | [Amazon Q Business API activity](https://docs.aws.amazon.com/amazonq/latest/business-use-dg/logging-using-cloudtrail.html#service-name-data-plane-events-cloudtrail) on an application. | Amazon Q Business application | AWS::QBusiness::Application | 
| Amazon Q Business | [Amazon Q Business API activity](https://docs.aws.amazon.com/amazonq/latest/business-use-dg/logging-using-cloudtrail.html#service-name-data-plane-events-cloudtrail) on a data source. | Amazon Q Business data source | AWS::QBusiness::DataSource | 
| Amazon Q Business | [Amazon Q Business API activity](https://docs.aws.amazon.com/amazonq/latest/business-use-dg/logging-using-cloudtrail.html#service-name-data-plane-events-cloudtrail) on an index. | Amazon Q Business index | AWS::QBusiness::Index | 
| Amazon Q Business | [Amazon Q Business API activity](https://docs.aws.amazon.com/amazonq/latest/business-use-dg/logging-using-cloudtrail.html#service-name-data-plane-events-cloudtrail) on a web experience. | Amazon Q Business web experience | AWS::QBusiness::WebExperience | 
| Amazon Q Business  | Amazon Q Business integration API activity. | **Amazon Q Business integration** | `AWS::QBusiness::Integration` | 
| Amazon Q Developer | Amazon Q Developer API activity on an integration. | Q Developer integration | AWS::QDeveloper::Integration | 
| Amazon Q Developer | [Amazon Q Developer API activity](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/logging_cw_api_calls.html#Q-Developer-Investigations-Cloudtrail) on operational investigations. | AIOps Investigation Group | AWS::AIOps::InvestigationGroup | 
| Amazon Quick | Amazon Quick API activity on an action connector. | AWSQuickSuite Actions | AWS::Quicksight::ActionConnector | 
| Amazon Quick | Amazon Quick Flow API activity. | **QuickSight flow** | `AWS::QuickSight::Flow` | 
| Amazon Quick | Amazon Quick FlowSession API activity. | **QuickSight flow session** | `AWS::QuickSight::FlowSession` | 
| Amazon SageMaker AI |  Amazon SageMaker AI [`InvokeEndpointWithResponseStream`](https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_runtime_InvokeEndpointWithResponseStream.html) activity on endpoints. | SageMaker AI endpoint | AWS::SageMaker::Endpoint | 
| Amazon SageMaker AI | Amazon SageMaker AI API activity on feature stores. | SageMaker AI feature store | AWS::SageMaker::FeatureGroup | 
| Amazon SageMaker AI | Amazon SageMaker AI API activity on [experiment trial components](https://docs.aws.amazon.com/sagemaker/latest/dg/experiments-monitoring.html). | SageMaker AI metrics experiment trial component | AWS::SageMaker::ExperimentTrialComponent | 
| Amazon SageMaker AI | Amazon SageMaker AI MLflow API activity. | **SageMaker MLflow** | `AWS::SageMaker::MlflowTrackingServer` | 
| AWS Signer | Signer API activity on signing jobs. | Signer signing job | AWS::Signer::SigningJob | 
| AWS Signer | Signer API activity on signing profiles. | Signer signing profile | AWS::Signer::SigningProfile | 
| Amazon Simple Email Service | Amazon Simple Email Service (Amazon SES) API activity on configuration sets. | SES configuration set | AWS::SES::ConfigurationSet | 
| Amazon Simple Email Service | Amazon Simple Email Service (Amazon SES) API activity on email identities. | SES identity | AWS::SES::EmailIdentity | 
| Amazon Simple Email Service | Amazon Simple Email Service (Amazon SES) API activity on templates. | SES template | AWS::SES::Template | 
| Amazon SimpleDB | Amazon SimpleDB API activity on domains. | SimpleDB domain | AWS::SDB::Domain | 
| AWS Step Functions | [Step Functions API activity](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cloud-trail.html#cloudtrail-data-events) on activities. | Step Functions | AWS::StepFunctions::Activity | 
| AWS Step Functions | [Step Functions API activity](https://docs.aws.amazon.com/step-functions/latest/dg/procedure-cloud-trail.html#cloudtrail-data-events) on state machines. | Step Functions state machine | AWS::StepFunctions::StateMachine | 
| AWS Systems Manager | [Systems Manager API activity](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html#cloudtrail-data-events) on control channels. | Systems Manager | AWS::SSMMessages::ControlChannel | 
| AWS Systems Manager | Systems Manager API activity on impact assessments. | SSM Impact Assessment  | AWS::SSM::ExecutionPreview | 
| AWS Systems Manager | [Systems Manager API activity](https://docs.aws.amazon.com/systems-manager/latest/userguide/monitoring-cloudtrail-logs.html#cloudtrail-data-events) on managed nodes. | Systems Manager managed node | AWS::SSM::ManagedNode | 
| Amazon Timestream | Amazon Timestream [`Query`](https://docs.aws.amazon.com/timestream/latest/developerguide/API_query_Query.html) API activity on databases. | Timestream database | AWS::Timestream::Database | 
| Amazon Timestream | Amazon Timestream API activity on regional endpoints. | Timestream regional endpoint | AWS::Timestream::RegionalEndpoint | 
| Amazon Timestream | Amazon Timestream [`Query`](https://docs.aws.amazon.com/timestream/latest/developerguide/API_query_Query.html) API activity on tables. | Timestream table | AWS::Timestream::Table | 
| Amazon Verified Permissions | Amazon Verified Permissions API activity on a policy store. | Amazon Verified Permissions | AWS::VerifiedPermissions::PolicyStore | 
| Amazon WorkSpaces Thin Client | WorkSpaces Thin Client API activity on a Device. | Thin Client Device | AWS::ThinClient::Device | 
| Amazon WorkSpaces Thin Client | WorkSpaces Thin Client API activity on an Environment. | Thin Client Environment | AWS::ThinClient::Environment | 
| AWS X-Ray | [X-Ray API activity](https://docs.aws.amazon.com/xray/latest/devguide/xray-api-cloudtrail.html#cloudtrail-data-events) on [traces](https://docs.aws.amazon.com/xray/latest/devguide/xray-concepts.html#xray-concepts-traces). | X-Ray trace | AWS::XRay::Trace | 
| Amazon AIDevOps | AIDevOps API activity on agent spaces. | Agent Space | AWS::AIDevOps::AgentSpace | 
| Amazon AIDevOps | AIDevOps API activity on associations. | AIDevOps association | AWS::AIDevOps::Association | 
| Amazon AIDevOps | AIDevOps API activity on operator app teams. | AIDevOps operator app team | AWS::AIDevOps::OperatorAppTeam | 
| Amazon AIDevOps | AIDevOps API activity on pipeline metadata. | AIDevOps Pipelines Metadata | AWS::AIDevOps::PipelineMetadata | 
| Amazon AIDevOps | AIDevOps API activity on services. | AIDevOps service | AWS::AIDevOps::Service | 
| Amazon Bedrock | Bedrock API activity on advanced optimize prompt jobs. | AdvancedOptimizePromptJob | AWS::Bedrock::AdvancedOptimizePromptJob | 
| Amazon Bedrock AgentCore | Bedrock AgentCore API activity on evaluators. | Bedrock-AgentCore Evaluator | AWS::BedrockAgentCore::Evaluator | 
| Amazon Cost Optimization | CloudOptimization API activity on profiles. | CloudOptimization Profile | AWS::CloudOptimization::Profile | 
| Amazon Cost Optimization | CloudOptimization API activity on recommendations. | CloudOptimization Recommendation | AWS::CloudOptimization::Recommendation | 
| Amazon GuardDuty | GuardDuty API activity on malware scans. | GuardDuty malware scan | AWS::GuardDuty::MalwareScan | 
| Amazon NovaAct | Amazon NovaAct API activity on workflow definitions. | Workflow definition | AWS::NovaAct::WorkflowDefinition | 
| Amazon NovaAct | Amanzon NovaAct API activity on workflow runs. | Workflow run | AWS::NovaAct::WorkflowRun | 
| Amazon Redshift | Redshift API activity on clusters. | Amazon Redshift Cluster | AWS::Redshift::Cluster | 
| Amazon Support | SupportAccess API activity on tenants. | SupportAccess tenant | AWS::SupportAccess::Tenant | 
| Amazon Support | SupportAccess API activity on trusting accounts. | SupportAccess trusting account | AWS::SupportAccess::TrustingAccount | 
| Amazon Support | SupportAccess API activity on trusting roles. | SupportAccess trusting role | AWS::SupportAccess::TrustingRole | 
| Amazon Transform | Transform API activity on agent instances. | Transform agent instance | AWS::Transform::AgentInstance | 
| Amazon Transform Custom | Transform Custom API activity on campaigns. | Transform-Custom campaign | AWS::TransformCustom::Campaign | 
| Amazon Transform Custom | Transform Custom API activity on conversations. | Transform-Custom conversation | AWS::TransformCustom::Conversation | 
| Amazon Transform Custom | Transform Custom API activity on knowledge items. | Transform-Custom knowledge item | AWS::TransformCustom::KnowledgeItem | 
| Amazon Transform Custom | Transform Custom API activity on packages. | Transform-Custom package | AWS::TransformCustom::Package | 
| Amazon WorkSpaces Applications | Agents accessing WorkSpaces Applications MCP tool events | Agent Access MCP Tools | AWS::AgentAccessMCP::Tools | 

Data events are not logged by default when you create a trail or event data store. To record CloudTrail data events, you must explicitly add the supported resources or resource types for which you want to collect activity. For more information, see [Creating a trail with the CloudTrail console](cloudtrail-create-a-trail-using-the-console-first-time.md) and [Create an event data store for CloudTrail events with the console](query-event-data-store-cloudtrail.md).

Additional charges apply for logging data events. For CloudTrail pricing, see [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/).

The following example shows a single log record of a data event for the Amazon SNS `Publish` action.

```
{
   "eventVersion": "1.09",
   "userIdentity": {
        "type": "AssumedRole",
        "principalId": "EX_PRINCIPAL_ID",
        "arn": "arn:aws:iam::123456789012:user/Bob",
        "accountId": "123456789012",
        "accessKeyId": "AKIAIOSFODNN7EXAMPLE",
        "sessionContext": {
        "sessionIssuer": {
            "type": "Role",
            "principalId": "AKIAIOSFODNN7EXAMPLE",
            "arn": "arn:aws:iam::123456789012:role/Admin",
            "accountId": "123456789012",
            "userName": "ExampleUser"
            },
            "attributes": {
                "creationDate": "2023-08-21T16:44:05Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2023-08-21T16:48:37Z",
    "eventSource": "sns.amazonaws.com",
    "eventName": "Publish",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "userAgent": "aws-cli/1.29.16 md/Botocore#1.31.16 ua/2.0 os/linux#5.4.250-173.369.amzn2int.x86_64 md/arch#x86_64 lang/python#3.8.17 md/pyimpl#CPython cfg/retry-mode#legacy botocore/1.31.16",
    "requestParameters": {
        "topicArn": "arn:aws:sns:us-east-1:123456789012:ExampleSNSTopic",
        "message": "HIDDEN_DUE_TO_SECURITY_REASONS",
        "subject": "HIDDEN_DUE_TO_SECURITY_REASONS",
        "messageStructure": "json",
        "messageAttributes": "HIDDEN_DUE_TO_SECURITY_REASONS"
    },
    "responseElements": {
        "messageId": "0787cd1e-d92b-521c-a8b4-90434e8ef840"
    },
    "requestID": "0a8ab208-11bf-5e01-bd2d-ef55861b545d",
    "eventID": "bb3496d4-5252-4660-9c28-3c6aebdb21c0",
    "readOnly": false,
    "resources": [{
        "accountId": "123456789012",
        "type": "AWS::SNS::Topic",
                "ARN": "arn:aws:sns:us-east-1:123456789012:ExampleSNSTopic"
    }],
    "eventType": "AwsApiCall",
    "managementEvent": false,
    "recipientAccountId": "123456789012",
    "eventCategory": "Data",
    "tlsDetails": {
        "tlsVersion": "TLSv1.2",
        "cipherSuite": "ECDHE-RSA-AES128-GCM-SHA256",
        "clientProvidedHostHeader": "sns.us-east-1.amazonaws.com"
    }
}
```

The next example shows a single log record of a data event for the Amazon Cognito `GetCredentialsForIdentity` action.

```
{
    "eventVersion": "1.08",
    "userIdentity": {
        "type": "Unknown"
    },
    "eventTime": "2023-01-19T16:55:08Z",
    "eventSource": "cognito-identity.amazonaws.com",
    "eventName": "GetCredentialsForIdentity",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.4",
    "userAgent": "aws-cli/2.7.25 Python/3.9.11 Darwin/21.6.0 exe/x86_64 prompt/off command/cognito-identity.get-credentials-for-identity",
    "requestParameters": {
        "logins": {
            "cognito-idp.us-east-1.amazonaws.com/us-east-1_aaaaaaaaa": "HIDDEN_DUE_TO_SECURITY_REASONS"
        },
        "identityId": "us-east-1:1cf667a2-49a6-454b-9e45-23199EXAMPLE"
    },
    "responseElements": {
        "credentials": {
            "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
            "sessionToken": "aAaAaAaAaAaAab1111111111EXAMPLE",
            "expiration": "Jan 19, 2023 5:55:08 PM"
        },
        "identityId": "us-east-1:1cf667a2-49a6-454b-9e45-23199EXAMPLE"
    },
    "requestID": "659dfc23-7c4e-4e7c-858a-1abce884d645",
    "eventID": "6ad1c766-5a41-4b28-b5ca-e223ccb00f0d",
    "readOnly": false,
    "resources": [{
        "accountId": "111122223333",
        "type": "AWS::Cognito::IdentityPool",
        "ARN": "arn:aws:cognito-identity:us-east-1:111122223333:identitypool/us-east-1:2dg778b3-50b7-565c-0f56-34200EXAMPLE"
    }],
    "eventType": "AwsApiCall",
    "managementEvent": false,
    "recipientAccountId": "111122223333",
    "eventCategory": "Data"
}
```

## Network activity events
<a name="cloudtrail-network-events"></a>

CloudTrail network activity events enable VPC endpoint owners to record AWS API calls made using their VPC endpoints from a private VPC to the AWS service. Network activity events provide visibility into the resource operations performed within a VPC.

You can log network activity events for the following services:
+ AWS AppConfig
+ AWS App Mesh
+ Amazon Athena
+ AWS B2B Data Interchange
+ AWS Backup gateway
+ Amazon Bedrock
+ Billing and Cost Management
+ AWS Pricing Calculator
+ AWS Cost Explorer
+ AWS Cloud Control API
+ AWS CloudHSM
+ AWS Cloud Map
+ AWS CloudFormation
+ AWS CloudTrail
+ Amazon CloudWatch
+ CloudWatch Application Signals
+ AWS CodeDeploy
+ Amazon Comprehend Medical
+ AWS Config
+ AWS Data Exports
+ Amazon Data Firehose
+ AWS Directory Service
+ Amazon DynamoDB
+ Amazon EC2
+ Amazon Elastic Container Service
+ Amazon Elastic File System
+ Elastic Load Balancing
+ Amazon EventBridge
+ Amazon EventBridge Scheduler
+ Amazon Fraud Detector
+ AWS Free Tier
+ Amazon FSx
+ AWS Glue
+ AWS HealthLake
+ AWS IoT FleetWise
+ AWS IoT Secure Tunneling
+ AWS Invoicing
+ Amazon Keyspaces (for Apache Cassandra)
+ AWS KMS
+ AWS Lake Formation
+ AWS Lambda
+ AWS License Manager
+ Amazon Lookout for Equipment
+ Amazon Lookout for Vision
+ Amazon Personalize
+ Amazon Q Business
+ Amazon Rekognition
+ Amazon Relational Database Service
+ Amazon S3
**Note**  
Amazon S3 [Multi-Region Access Points](https://docs.aws.amazon.com/AmazonS3/latest/userguide/MultiRegionAccessPointRequests.html) are not supported.
+ Amazon SageMaker AI
+ AWS Secrets Manager
+ Amazon Simple Notification Service
+ Amazon Simple Queue Service
+ Amazon Simple Workflow Service
+ AWS Storage Gateway
+ AWS Systems Manager Incident Manager
+ Amazon Textract
+ Amazon Transcribe
+ Amazon Translate
+ AWS Transform
+ Amazon Verified Permissions
+ Amazon WorkMail

Network activity events are not logged by default when you create a trail or event data store. To record CloudTrail network activity events, you must explicitly set the event source for which you want to collect activity. For more information, see [Logging network activity events](logging-network-events-with-cloudtrail.md).

Additional charges apply for logging network activity events. For CloudTrail pricing, see [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/).

The following example shows a successful AWS KMS `ListKeys` event that traversed a VPC endpoint. The `vpcEndpointId` field shows the ID of the VPC endpoint. The `vpcEndpointAccountId` field shows the account ID of the VPC endpoint owner. In this example, the request was made by the VPC endpoint owner.

```
{
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "AssumedRole",
        "principalId": "ASIAIOSFODNN7EXAMPLE:role-name",
        "arn": "arn:aws:sts::123456789012:assumed-role/Admin/role-name",
        "accountId": "123456789012",
        "accessKeyId": "ASIAIOSFODNN7EXAMPLE",
        "sessionContext": {
            "sessionIssuer": {
                "type": "Role",
                "principalId": "ASIAIOSFODNN7EXAMPLE",
                "arn": "arn:aws:iam::123456789012:role/Admin",
                "accountId": "123456789012",
                "userName": "Admin"
            },
            "attributes": {
                "creationDate": "2024-06-04T23:10:46Z",
                "mfaAuthenticated": "false"
            }
        }
    },
    "eventTime": "2024-06-04T23:12:50Z",
    "eventSource": "kms.amazonaws.com",
    "eventName": "ListKeys",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "requestID": "16bcc089-ac49-43f1-9177-EXAMPLE23731",
    "eventID": "228ca3c8-5f95-4a8a-9732-EXAMPLE60ed9",
    "eventType": "AwsVpceEvent",
    "recipientAccountId": "123456789012",
    "sharedEventID": "a1f3720c-ef19-47e9-a5d5-EXAMPLE8099f",
    "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
    "vpcEndpointAccountId": "123456789012",
    "eventCategory": "NetworkActivity"
}
```<a name="network-event-example"></a>

The next example shows an unsuccessful AWS KMS `ListKeys` event with a VPC endpoint policy violation. Because a VPC policy violation occurred, both the `errorCode` and `errorMessage` fields are present. The account ID in the `recipientAccountId` and `vpcEndpointAccountId` fields is the same, which indicates the event was sent to the VPC endpoint owner. The `accountId` in the `userIdentity` element is not the `vpcEndpointAccountId`, which indicates that the user making the request is not the VPC endpoint owner.

```
{
    "eventVersion": "1.09",
    "userIdentity": {
        "type": "AWSAccount",
        "principalId": "AKIAIOSFODNN7EXAMPLE",
        "accountId": "777788889999"
    },
    "eventTime": "2024-07-15T23:57:12Z",
    "eventSource": "kms.amazonaws.com",
    "eventName": "ListKeys",
    "awsRegion": "us-east-1",
    "sourceIPAddress": "192.0.2.0",
    "errorCode": "VpceAccessDenied",
    "errorMessage": "The request was denied due to a VPC endpoint policy",
    "requestID": "899003b8-abc4-42bb-ad95-EXAMPLE0c374",
    "eventID": "7c6e3d04-0c3b-42f2-8589-EXAMPLE826c0",
    "eventType": "AwsVpceEvent",
    "recipientAccountId": "123456789012",
    "sharedEventID": "702f74c4-f692-4bfd-8491-EXAMPLEb1ac4",
    "vpcEndpointId": "vpce-EXAMPLE08c1b6b9b7",
    "vpcEndpointAccountId": "123456789012",
    "eventCategory": "NetworkActivity"
}
```

## Insights events
<a name="cloudtrail-insights-events"></a>

CloudTrail Insights events capture unusual API call rate or error rate activity in your AWS account by analyzing CloudTrail management activity. Insights events provide relevant information, such as the associated API, error code, incident time, and statistics, that help you understand and act on unusual activity. Unlike other types of events captured in a CloudTrail trail or event data store, Insights events are logged only when CloudTrail detects changes in your account's API usage or error rate logging that differ significantly from the account's typical usage patterns. For more information, see [Working with CloudTrail Insights](logging-insights-events-with-cloudtrail.md).

Examples of activity that might generate Insights events include:
+ Your account typically logs no more than 20 Amazon S3 `deleteBucket` API calls per minute, but your account starts to log an average of 100 `deleteBucket` API calls per minute. An Insights event is logged at the start of the unusual activity, and another Insights event is logged to mark the end of the unusual activity.
+ Your account typically logs 20 calls per minute to the Amazon EC2 `AuthorizeSecurityGroupIngress` API, but your account starts to log zero calls to `AuthorizeSecurityGroupIngress`. An Insights event is logged at the start of the unusual activity, and ten minutes later, when the unusual activity ends, another Insights event is logged to mark the end of the unusual activity.
+ Your account typically logs less than one `AccessDeniedException` error in a seven-day period on the AWS Identity and Access Management API, `DeleteInstanceProfile`. Your account starts to log an average of 12 `AccessDeniedException` errors per minute on the `DeleteInstanceProfile` API call. An Insights event is logged at the start of the unusual error rate activity, and another Insights event is logged to mark the end of the unusual activity.

These examples are provided for illustration purposes only. Your results may vary depending on your use case.

To log CloudTrail Insights events, you must explicitly enable Insights events on a new or existing trail or event data store. For more information about creating a trail, see [Creating a trail with the CloudTrail console](cloudtrail-create-a-trail-using-the-console-first-time.md). For more information about creating an event data store, see [Create an event data store for Insights events with the console](query-event-data-store-insights.md).

Additional charges apply for Insights events. You will be charged separately if you enable Insights for both trails and event data stores. For more information, see [AWS CloudTrail Pricing](https://aws.amazon.com/cloudtrail/pricing/).

There are two events logged to show unusual activity in CloudTrail Insights: a start event and an end event. The following example shows a single log record of a starting Insights event that occurred when the Application Auto Scaling API `CompleteLifecycleAction` was called an unusual number of times. For Insights events, the value of `eventCategory` is `Insight`. An `insightDetails` block identifies the event state, source, name, Insights type, and context, including statistics and attributions. For more information about the `insightDetails` block, see [CloudTrail record contents for Insights events for trails](cloudtrail-insights-fields-trails.md).

```
{
        "eventVersion": "1.08",
        "eventTime": "2023-07-10T01:42:00Z",
        "awsRegion": "us-east-1",
        "eventID": "55ed45c5-0b0c-4228-9fe5-EXAMPLEc3f4d",
        "eventType": "AwsCloudTrailInsight",
        "recipientAccountId": "123456789012",
        "sharedEventID": "979c82fe-14d4-4e4c-aa01-EXAMPLE3acee",
        "insightDetails": {
            "state": "Start",
            "eventSource": "autoscaling.amazonaws.com",
            "eventName": "CompleteLifecycleAction",
            "insightType": "ApiCallRateInsight",
            "insightContext": {
                "statistics": {
                    "baseline": {
                        "average": 9.82222E-5
                    },
                    "insight": {
                        "average": 5.0
                    },
                    "insightDuration": 1,
                    "baselineDuration": 10181
                },
                "attributions": [{
                    "attribute": "userIdentityArn",
                    "insight": [{
                        "value": "arn:aws:sts::123456789012:assumed-role/CodeDeployRole1",
                        "average": 5.0
                    }, {
                        "value": "arn:aws:sts::123456789012:assumed-role/CodeDeployRole2",
                        "average": 5.0
                    }, {
                        "value": "arn:aws:sts::123456789012:assumed-role/CodeDeployRole3",
                        "average": 5.0
                    }],
                    "baseline": [{
                        "value": "arn:aws:sts::123456789012:assumed-role/CodeDeployRole1",
                        "average": 9.82222E-5
                    }]
                }, {
                    "attribute": "userAgent",
                    "insight": [{
                        "value": "codedeploy.amazonaws.com",
                        "average": 5.0
                    }],
                    "baseline": [{
                        "value": "codedeploy.amazonaws.com",
                        "average": 9.82222E-5
                    }]
                }, {
                    "attribute": "errorCode",
                    "insight": [{
                        "value": "null",
                        "average": 5.0
                    }],
                    "baseline": [{
                        "value": "null",
                        "average": 9.82222E-5
                    }]
                }]
            }
        },
        "eventCategory": "Insight"
    }
```