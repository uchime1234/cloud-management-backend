import requests
import json
import logging
import ssl
import urllib3
import time
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from django.core.cache import cache
import time

logger = logging.getLogger(__name__)

# Try to import certifi, but handle if it's not available
try:
    import certifi
    HAS_CERTIFI = True
except ImportError:
    HAS_CERTIFI = False
    logger.warning("certifi not installed. SSL verification may fail.")

# Disable SSL warnings (for development only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SSLAdapter(HTTPAdapter):
    """
    Custom adapter to handle SSL issues on Windows
    """
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        # For development only - don't use in production
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        kwargs['ssl_context'] = ctx
        return super().init_poolmanager(*args, **kwargs)

class GitHubService:
    def __init__(self, access_token=None):
        self.access_token = access_token
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        self.headers = {
            'Authorization': f'Bearer {access_token}',
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CloudManagementApp/1.0'  # GitHub requires a User-Agent
        } if access_token else {'User-Agent': 'CloudManagementApp/1.0'}
        
        # Create a session with custom SSL handling
        self.session = requests.Session()
        
        # Try to use the custom SSL adapter
        try:
            self.session.mount('https://', SSLAdapter())
        except Exception as e:
            logger.warning(f"Failed to mount SSL adapter: {e}")

    def _check_rate_limit(self, response):
        """Track rate limit from response headers"""
        if 'X-RateLimit-Remaining' in response.headers:
            self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
        if 'X-RateLimit-Reset' in response.headers:
            self.rate_limit_reset = int(response.headers['X-RateLimit-Reset'])
        
        if self.rate_limit_remaining and self.rate_limit_remaining < 10:
            reset_time = datetime.fromtimestamp(self.rate_limit_reset)
            logger.warning(f"GitHub API rate limit low: {self.rate_limit_remaining} remaining, resets at {reset_time}")
            return False
        return True
        
    def _make_request(self, method, url, **kwargs):
        """
        Helper method to make requests with proper error handling and retries
        """
        # Set default timeout
        kwargs.setdefault('timeout', 30)
        
        # Always use verify=False for development to avoid SSL issues on Windows
        kwargs['verify'] = False
        
        max_retries = 2
        for attempt in range(max_retries):
            try:
                response = self.session.request(method, url, headers=self.headers, **kwargs)
                
                # Check for rate limiting
                if self.rate_limit_remaining == 0:
                    reset_time = datetime.fromtimestamp(self.rate_limit_reset)
                    wait_seconds = (reset_time - datetime.now()).total_seconds()
                    if wait_seconds > 0:
                        logger.warning(f"Rate limited. Waiting {wait_seconds} seconds...")
                        time.sleep(min(wait_seconds, 60))
                
                # Handle 404 gracefully
                if response.status_code == 404:
                    return None
                
                response.raise_for_status()
                return response.json() if response.content else None
                
            except requests.exceptions.SSLError as e:
                logger.warning(f"SSL error on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(0.5)
                continue
            except requests.exceptions.ConnectionError as e:
                logger.warning(f"Connection error on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(0.5)
                continue
            except requests.exceptions.Timeout as e:
                logger.warning(f"Timeout error on attempt {attempt + 1}: {e}")
                if attempt == max_retries - 1:
                    return None
                time.sleep(0.5)
                continue
            except requests.exceptions.HTTPError as e:
                if hasattr(response, 'status_code') and response.status_code == 403:
                    logger.warning(f"Rate limit or permission error: {e}")
                    return None
                logger.error(f"HTTP error {response.status_code if hasattr(response, 'status_code') else 'unknown'}: {e}")
                return None
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
                return None
        
        return None

    def get_user_repos(self, page=1, per_page=100):
        """
        Get user's repositories with pagination support
        """
        try:
            all_repos = []
            current_page = page
            max_pages = 5  # Limit to 5 pages to avoid rate limits
            
            while current_page <= max_pages:
                url = f"https://api.github.com/user/repos?page={current_page}&per_page={per_page}&sort=updated&direction=desc"
                result = self._make_request('GET', url)
                
                if result is None:
                    break
                    
                if isinstance(result, list):
                    all_repos.extend(result)
                    
                    # Check if we got less than per_page, meaning last page
                    if len(result) < per_page:
                        break
                    
                    current_page += 1
                else:
                    break
            
            logger.info(f"Successfully fetched {len(all_repos)} repositories")
            return all_repos
            
        except Exception as e:
            logger.error(f"Failed to fetch repos: {e}")
            return []
    
    def get_repo_details(self, owner, repo):
        """
        Get details about a specific repository
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}"
            return self._make_request('GET', url)
        except Exception as e:
            logger.error(f"Failed to fetch repo details: {e}")
            return None
    
    def get_repo_contents(self, owner, repo, path="", max_depth=2, current_depth=0):
        """
        Get contents of a repository to check for Terraform files with depth limit
        """
        if current_depth >= max_depth:
            return []
            
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
            result = self._make_request('GET', url)
            
            if result is None:
                return []
                
            return result
            
        except Exception as e:
            logger.error(f"Failed to fetch repo contents for {owner}/{repo}/{path}: {e}")
            return []
    
    # Add caching for Terraform detection results

    
    def has_terraform_files(self, owner, repo, max_depth=2):
        """
        Check if repository contains Terraform files - with caching
        """
        # Check cache first (cache for 24 hours to avoid repeated API calls)
        cache_key = f"github_terraform_{owner}_{repo}"
        cached_result = cache.get(cache_key)
        
        if cached_result is not None:
            logger.info(f"📦 Using cached result for {owner}/{repo}: {cached_result}")
            return cached_result
        
        # Small delay to make progress visible in UI
        time.sleep(0.1)
        
        try:
            # Method 1: Check root directory for .tf files
            contents = self.get_repo_contents(owner, repo, max_depth=1)
            if contents and isinstance(contents, list):
                # Check for Terraform files in root
                for item in contents:
                    item_name = item.get('name', '').lower()
                    # Check for .tf or .tfvars files
                    if item_name.endswith('.tf') or item_name.endswith('.tfvars'):
                        logger.info(f"✅ Found Terraform file in root: {item.get('path')}")
                        cache.set(cache_key, True, timeout=86400)  # Cache for 24 hours
                        return True
                    
                    # Check for Terraform directories to scan deeper
                    if item.get('type') == 'dir' and item_name in ['terraform', 'tf', 'infrastructure', 'iac', 'infra', 'provisioning', 'modules']:
                        # Scan this directory deeper
                        sub_contents = self.get_repo_contents(owner, repo, item.get('path', ''), max_depth=2, current_depth=1)
                        if isinstance(sub_contents, list):
                            for sub in sub_contents:
                                if sub.get('name', '').lower().endswith('.tf'):
                                    logger.info(f"✅ Found Terraform file in {item.get('path')}: {sub.get('name')}")
                                    cache.set(cache_key, True, timeout=86400)
                                    return True
            
            # Method 2: Check if repository has any .tf files using search API (more thorough)
            try:
                search_url = f"https://api.github.com/search/code?q=extension:tf+repo:{owner}/{repo}"
                search_result = self._make_request('GET', search_url)
                if search_result and search_result.get('total_count', 0) > 0:
                    logger.info(f"✅ Found {search_result['total_count']} .tf files via search in {owner}/{repo}")
                    cache.set(cache_key, True, timeout=86400)
                    return True
            except Exception as e:
                logger.debug(f"Search API failed for {owner}/{repo}: {e}")
            
            # Method 3: Check for Terraform files in common paths
            common_paths = ['terraform/', 'tf/', 'infrastructure/', 'iac/', 'infra/', 'provisioning/', 'modules/']
            for path in common_paths:
                try:
                    path_contents = self.get_repo_contents(owner, repo, path, max_depth=1, current_depth=1)
                    if path_contents and isinstance(path_contents, list):
                        for item in path_contents:
                            if item.get('name', '').lower().endswith('.tf'):
                                logger.info(f"✅ Found Terraform file in {path}: {item.get('name')}")
                                cache.set(cache_key, True, timeout=86400)
                                return True
                except Exception:
                    continue
            
            cache.set(cache_key, False, timeout=86400)  # Cache negative results too
            return False
            
        except Exception as e:
            logger.error(f"Error checking Terraform files for {owner}/{repo}: {e}")
            cache.set(cache_key, False, timeout=3600)  # Cache errors for 1 hour
            return False

    def get_pull_requests(self, owner, repo, state='closed', per_page=30):
        """
        Get merged pull requests from repository
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls?state={state}&per_page={per_page}&sort=updated&direction=desc"
            result = self._make_request('GET', url)
            
            if not result:
                return []
                
            # Filter only merged PRs
            merged_pulls = [p for p in result if p.get('merged_at')]
            logger.info(f"Found {len(merged_pulls)} merged PRs out of {len(result)} total")
            return merged_pulls
            
        except Exception as e:
            logger.error(f"Failed to fetch pull requests: {e}")
            return []
    
    def get_pr_files(self, owner, repo, pr_number):
        """
        Get files changed in a specific pull request
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
            result = self._make_request('GET', url)
            return result if result else []
            
        except Exception as e:
            logger.error(f"Failed to fetch PR files: {e}")
            return []
    
    def create_webhook(self, owner, repo, webhook_url):
        """
        Create a webhook for the repository
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/hooks"
            payload = {
                "name": "web",
                "active": True,
                "events": ["pull_request"],
                "config": {
                    "url": webhook_url,
                    "content_type": "json",
                    "secret": settings.GITHUB_WEBHOOK_SECRET
                }
            }
            result = self._make_request('POST', url, json=payload)
            return result
            
        except Exception as e:
            logger.error(f"Failed to create webhook: {e}")
            return None
    
    def delete_webhook(self, owner, repo, webhook_id):
        """
        Delete a webhook from the repository
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/hooks/{webhook_id}"
            response = self.session.delete(url, headers=self.headers, timeout=30, verify=False)
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Failed to delete webhook: {e}")
            return False
    
    def get_services_from_files(self, files_changed):
        """
        Determine which AWS services are affected based on changed files
        """
        services = set()
        file_paths = [f.get('filename', '') for f in files_changed]
        
        service_patterns = {
            'EC2': ['ec2', 'instance', 'ami', 'key-pair'],
            'S3': ['s3', 'bucket', 'object'],
            'RDS': ['rds', 'database', 'postgres', 'mysql'],
            'VPC': ['vpc', 'subnet', 'nat', 'route-table', 'security-group'],
            'Lambda': ['lambda', 'serverless', 'function'],
            'Load Balancer': ['alb', 'elb', 'loadbalancer', 'target-group'],
            'Data Transfer': ['data', 'transfer', 'cloudfront'],
            'CloudWatch': ['cloudwatch', 'alarm', 'dashboard'],
            'IAM': ['iam', 'role', 'policy', 'user'],
            'DynamoDB': ['dynamodb', 'table'],
            'ECS': ['ecs', 'cluster', 'service', 'task-definition'],
            'EKS': ['eks', 'cluster', 'node-group'],
        }
        
        for path in file_paths:
            path_lower = path.lower()
            for service, patterns in service_patterns.items():
                if any(pattern in path_lower for pattern in patterns):
                    services.add(service)
        
        return list(services)
    
    # Add this method to the GitHubService class in github_service.py

    def get_file_content(self, owner, repo, file_path):
        """
        Get content of a specific file from a repository
        """
        try:
            url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
            result = self._make_request('GET', url)
            
            # Decode base64 content if present
            if result and 'content' in result:
                import base64
                decoded = base64.b64decode(result['content']).decode('utf-8')
                return decoded
            return None
        except Exception as e:
            logger.error(f"Failed to get file content for {owner}/{repo}/{file_path}: {e}")
            return None
        

# github_service.py

def exchange_code_for_token(code):
    """
    Exchange OAuth code for GitHub access token with retry logic
    """
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            url = "https://github.com/login/oauth/access_token"
            
            # Make sure you're using the correct redirect URI
            payload = {
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URL,  # Add this!
            }
            
            headers = {
                "Accept": "application/json",
                "User-Agent": "CloudManagementApp/1.0"
            }
            
            print(f"🔄 Exchanging code for token...")
            print(f"   Client ID: {settings.GITHUB_CLIENT_ID}")
            print(f"   Redirect URI: {settings.GITHUB_REDIRECT_URL}")
            
            response = requests.post(url, data=payload, headers=headers, timeout=30, verify=False)
            
            print(f"   Response status: {response.status_code}")
            
            response.raise_for_status()
            data = response.json()
            
            if 'access_token' in data:
                print(f"✅ Successfully exchanged code for token")
                return data['access_token']
            else:
                print(f"❌ Token exchange failed: {data}")
                if attempt == max_retries - 1:
                    return None
                    
        except requests.exceptions.RequestException as e:
            print(f"❌ Request failed (attempt {attempt + 1}): {e}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
            retry_delay *= 2
    
    return None

def get_user_from_token(access_token):
    """
    Get GitHub user info from access token with retry logic
    """
    max_retries = 3
    retry_delay = 2
    
    for attempt in range(max_retries):
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "CloudManagementApp/1.0"
            }
            
            # Always use verify=False for Windows compatibility
            response = requests.get("https://api.github.com/user", headers=headers, timeout=30, verify=False)
            response.raise_for_status()
            
            data = response.json()
            logger.info(f"Successfully fetched user: {data.get('login')}")
            return data
            
        except requests.exceptions.SSLError as e:
            logger.warning(f"SSL error on attempt {attempt + 1}: {e}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
            retry_delay *= 2
            
        except Exception as e:
            logger.error(f"Failed to get user from token: {e}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
    
    return None


def sync_repo_deployments(repo_id):
    """
    Sync recent deployments for a repository
    """
    try:
        from .models import GitHubRepo
        repo = GitHubRepo.objects.get(id=repo_id)
    except Exception as e:
        print(f"Error getting repo for sync: {e}")
        return
    
    github = GitHubService(repo.access_token)
    owner, repo_name = repo.repo_full_name.split('/')
    
    # Get recent merged PRs
    pulls = github.get_pull_requests(owner, repo_name, state='closed', per_page=30)
    
    for pr in pulls:
        pr_number = pr.get('number')
        pr_title = pr.get('title')
        pr_url = pr.get('html_url')
        merged_by = pr.get('merged_by', {}).get('login', 'unknown')
        merged_at = pr.get('merged_at')
        
        if not merged_at:
            continue
        
        # Get files changed
        files = github.get_pr_files(owner, repo_name, pr_number)
        
        # Determine services affected
        services_affected = github.get_services_from_files(files)
        
        # Save or update
        from .models import DeploymentEvent
        DeploymentEvent.objects.update_or_create(
            repo=repo,
            pr_number=pr_number,
            defaults={
                'aws_account': repo.aws_account,
                'pr_title': pr_title,
                'pr_url': pr_url,
                'merged_by': merged_by,
                'merged_at': merged_at,
                'files_changed': files,
                'services_affected': services_affected
            }
        )
    
    repo.last_sync_at = timezone.now()
    repo.save()
