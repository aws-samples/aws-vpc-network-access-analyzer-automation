import boto3
import logging

# Initialize logger
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Initialize boto3 session
session = boto3.Session()
session._loader._search_paths.insert(0, 'models')
ec2 = session.client('ec2', region_name='us-east-1')

def lambda_handler(event, context):

    scope_analysis_details_list = event['scope_analysis_details']
    print(scope_analysis_details_list)

    analysis_completed = True

    if len(scope_analysis_details_list):
        for item in scope_analysis_details_list:
            logger.info("printing item next>>>")
            print(item)
            scope_analysis_id = item["scope_analysis_id"]
            response = ec2.describe_network_insights_access_scope_analyses(NetworkInsightsAccessScopeAnalysisIds=[scope_analysis_id])
            status = response['NetworkInsightsAccessScopeAnalyses'][0]['Status']

            if status == 'running':
                analysis_completed = False
                break
    

    return analysis_completed
        
