import boto3
import datetime
import logging
import json

# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 session
session = boto3.Session()
session._loader._search_paths.insert(0, 'models')
ec2 = session.client('ec2', region_name='us-east-1')

security_hub_client = boto3.client('securityhub')

def lambda_handler(event, context):

    # Initalize Security Hub Findings
    security_hub_findings = []
    
    # get the account id, region, scope ids and analysis ids from the event object
    account_id = event['account']
    region_id = event['region']
    scope_analysis_details_list = event['scope_analysis_details']

    # updated list with the finding count
    updated_scope_analysis_details_list = []

    if len(scope_analysis_details_list):
        for item in scope_analysis_details_list:
            # retrieve scope id and analysis id
            scope_id = item['scope_id']
            scope_analysis_id = item['scope_analysis_id']

            # initialize the variable to check if finings have been senet to Security Hub
            if "findings_processed4sh" in item.keys():
                findings_processed4sh = item['findings_processed4sh']
            else:
                findings_processed4sh = False

            # get network analysis findings
            network_insight_findings = ec2.get_network_insights_access_scope_analysis_findings(NetworkInsightsAccessScopeAnalysisId=scope_analysis_id)
            print("findings>> "+json.dumps(network_insight_findings))
            analysis_status = network_insight_findings['AnalysisStatus']
            analysis_findings = network_insight_findings['AnalysisFindings']
            

            # construct security hub finding
            findings_count = len(analysis_findings)
            if findings_processed4sh == False and analysis_status == 'succeeded' and findings_count > 0:
                findings_source_destination = generate_source_destination_resources(analysis_findings)
                security_hub_finding_item = construct_security_hub_finding(scope_id, scope_analysis_id, findings_source_destination, findings_count, account_id, region_id)
                security_hub_findings.append(security_hub_finding_item)
                findings_processed4sh = True

            updated_scope_analysis_details_list.append({
                'scope_id': scope_id,
                'scope_analysis_id': scope_analysis_id,
                'analysis_status': analysis_status,
                'findings_count': findings_count,
                'findings_processed4sh': findings_processed4sh
            })

        if len(security_hub_findings):
            # send findings to security hub
            security_hub_response = security_hub_client.batch_import_findings(
                Findings = security_hub_findings
            )
            logger.info("Response from sending findings to security hub")
            logger.info("successful upload" + str(security_hub_response["SuccessCount"]))
            logger.info("failed upload" + str(security_hub_response["FailedCount"]))

    return updated_scope_analysis_details_list


def generate_source_destination_resources(analysis_findings):
    
    findings_source_destination = []
    
    if(len(analysis_findings) > 0):

        # Identify the source and destination for each finding
        for finding in analysis_findings:
            finding_id = finding["FindingId"]
            finding_components = finding["FindingComponents"]
            source = finding_components[0]["Component"]["Id"]
            destination = finding_components[len(finding_components) - 1]["Component"]["Id"]

            # Add finding details to the array
            findings_source_destination.append({
                "FindingId": finding_id,
                "Route":{
                    "Source": source,
                    "Destination": destination
                }
            })
            print("findings_source_destinations >> " + json.dumps(findings_source_destination))
        return {
            "FindingRoutes": findings_source_destination
        }
    return {}

def construct_security_hub_finding(scope_id, scope_analysis_id, findings_source_destination, findings_count, account_id, region_id):
    
    # Initialize date time 
    d = datetime.datetime.utcnow()

    security_hub_finding_item = {
        "SchemaVersion": "2018-10-08",
        "Title": f"Match Found for Scope Id {scope_id}",
        "Description": "You current network configuration does not align with your compliance rules defined in Network Access Analyzer",
        "ProductArn": f"arn:aws:securityhub:{region_id}:{account_id}:product/{account_id}/default",
        "AwsAccountId": account_id,
        "ProductName": "NetworkAccessAnalyzer",
        "Id": f"scope-analysis-id/{scope_id}", 
        "GeneratorId": "CUSTOM:AutomatedScopeCheckerTool",
        "CreatedAt": d.isoformat("T") + "Z",
        "UpdatedAt": d.isoformat("T") + "Z",
        "FindingProviderFields": {
            "Severity": {
                "Label": "MEDIUM",
            },
            "Types": [
                "Software and Configuration Checks/Vulnerabilities/CVE"
            ]
        },
        "ProductFields":{
            "vpcaa-autorun/networkaccessanalyzer/securityhub/NetworkScopeAnalysisId": f"{scope_analysis_id}",
            "vpcaa-autorun/networkaccessanalyzer/securityhub/NetworkScopeAnalysisFindingsCount": f"{findings_count}",
            "vpcaa-autorun/networkaccessanalyzer/securityhub/NetworkScopeAnalysisFindingsRoute": f"{json.dumps(findings_source_destination)}"
        },
        "Resources": [{
            "Type": "NetworkAccessAnalyzerNetworkAccessScopeId",    
            "Id": f"arn:aws:ec2:{region_id}:{account_id}:network-insights-access-scope-analysis/{scope_id}"
        }]
    }
    return security_hub_finding_item

