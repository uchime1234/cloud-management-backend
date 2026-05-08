import boto3
from botocore.exceptions import ClientError
from django.conf import settings

def assume_role(role_arn, external_id):
    """
    Assumes an IAM role and returns temporary credentials.
    """
    try:
        print(f"🔍 DEBUG: assume_role called")
        print(f"🔍 DEBUG: role_arn: '{role_arn}'")
        print(f"🔍 DEBUG: external_id: {external_id}")
    
        # Add validation
        if not role_arn or len(role_arn) < 20:
            print(f"❌ Invalid role ARN: '{role_arn}'")
            raise ValueError(f"Invalid role ARN: {role_arn}")
        
        # Create STS client using credentials from settings.py
        sts = boto3.client(
            "sts",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_REGION
        )
        
        print(f"🔍 DEBUG: Calling sts.assume_role...")
        response = sts.assume_role(
            RoleArn=role_arn,
            RoleSessionName="CostSession",
            ExternalId=str(external_id)
        )
        
        credentials = response["Credentials"]
        print(f"🔍 DEBUG: assume_role successful, got credentials")
        
        # Return just the credentials (NOT a client)
        return {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretAccessKey"],
            "SessionToken": credentials["SessionToken"],
        }
        
    except ClientError as e:
        print(f"STS AssumeRole Error: {e}")
        raise
    except Exception as e:
        print(f"Unexpected error in assume_role: {e}")
        raise

def test_connection(credentials):
    """
    Tests if credentials work by getting caller identity.
    This is a simple test that doesn't require Cost Explorer.
    """
    try:
        sts = boto3.client(
            "sts",
            aws_access_key_id=credentials["AccessKeyId"],
            aws_secret_access_key=credentials["SecretAccessKey"],
            aws_session_token=credentials["SessionToken"],
            region_name=settings.AWS_REGION
        )
        
        identity = sts.get_caller_identity()
        return {
            "success": True,
            "account_id": identity["Account"],
            "user_id": identity["UserId"],
            "arn": identity["Arn"]
        }
    except Exception as e:
        print(f"Connection test failed: {e}")
        raise