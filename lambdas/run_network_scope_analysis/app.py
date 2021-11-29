import boto3

# Initialize boto3 session
session = boto3.Session()
session._loader._search_paths.insert(0, 'models')
ec2 = session.client('ec2', region_name='us-east-1')

def lambda_handler(event, context):

    scope_analysis_details = []

    # describe all current analyses
    response = ec2.describe_network_insights_access_scope_analyses()

    analysis_ids = [analysis['NetworkInsightsAccessScopeAnalysisId'] for analysis in response['NetworkInsightsAccessScopeAnalyses']]

    print(f'Analysis Ids: {analysis_ids}')

    for analysis_id in analysis_ids:
        print(f'Deleting analysis {analysis_id} ...')
        ec2.delete_network_insights_access_scope_analysis(NetworkInsightsAccessScopeAnalysisId=analysis_id)

    # get all network insight scopes
    response = ec2.describe_network_insights_access_scopes()
    scope_ids = [scope['NetworkInsightsAccessScopeId'] for scope in response['NetworkInsightsAccessScopes']]

    print(f'Scope Ids: {scope_ids}')

    # start network insight scope analysis
    for scope_id in scope_ids:
        response = ec2.start_network_insights_access_scope_analysis(NetworkInsightsAccessScopeId=scope_id)
        scope_analysis_id = response['NetworkInsightsAccessScopeAnalysis']['NetworkInsightsAccessScopeAnalysisId']
        scope_analysis_details.append(
            {
                "scope_id": scope_id,
                "scope_analysis_id": scope_analysis_id
            }
        )

    return scope_analysis_details
