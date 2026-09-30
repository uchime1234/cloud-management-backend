# myground/github_service.py

import requests
import json
import logging
import ssl
import time
import hmac
import hashlib
import base64
from datetime import datetime
from django.conf import settings
from django.utils import timezone
from django.core.cache import cache
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

try:
    import certifi
    HAS_CERTIFI = True
except ImportError:
    HAS_CERTIFI = False
    logger.warning("certifi not installed. SSL verification may fail.")


def _verify_tls():
    """TLS verify flag — False only in DEBUG."""
    return not getattr(settings, 'DEBUG', False)


class GitHubAPIError(Exception):
    """Raised when GitHub returns an unexpected status."""
    pass


class GitHubService:
    def __init__(self, access_token=None):
        self.access_token = access_token
        self.rate_limit_remaining = None
        self.rate_limit_reset = None
        self.headers = {
            'Accept': 'application/vnd.github.v3+json',
            'User-Agent': 'CloudManagementApp/1.0',
        }
        if access_token:
            self.headers['Authorization'] = f'Bearer {access_token}'

        self.session = requests.Session()

    def _check_rate_limit(self, response):
        if 'X-RateLimit-Remaining' in response.headers:
            self.rate_limit_remaining = int(response.headers['X-RateLimit-Remaining'])
        if 'X-RateLimit-Reset' in response.headers:
            self.rate_limit_reset = int(response.headers['X-RateLimit-Reset'])

    def _make_request(self, method, url, raise_on_error=False, **kwargs):
        """
        Generic request. Returns parsed JSON on 2xx, None on 404.
        Raises GitHubAPIError if raise_on_error=True and status >= 400.
        """
        kwargs.setdefault('timeout', 30)
        kwargs.setdefault('verify', _verify_tls())

        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = self.session.request(
                    method, url, headers=self.headers, **kwargs
                )
                self._check_rate_limit(response)

                if response.status_code == 404:
                    return None

                if response.status_code in (200, 201):
                    return response.json() if response.content else None

                if response.status_code == 403:
                    if self.rate_limit_remaining == 0 and self.rate_limit_reset:
                        wait = max(0, self.rate_limit_reset - int(time.time()))
                        if 0 < wait < 60:
                            logger.warning(f"Rate limited. Waiting {wait}s.")
                            time.sleep(wait)
                            continue
                    logger.warning(f"403 on {url}: {response.text[:200]}")
                    if raise_on_error:
                        raise GitHubAPIError(f"403: {response.text[:200]}")
                    return None

                if raise_on_error:
                    raise GitHubAPIError(
                        f"{response.status_code}: {response.text[:200]}"
                    )
                logger.error(f"GitHub API {response.status_code}: {url}")
                return None

            except (requests.exceptions.SSLError,
                    requests.exceptions.ConnectionError,
                    requests.exceptions.Timeout) as e:
                logger.warning(f"Network error (attempt {attempt+1}): {e}")
                if attempt == max_retries - 1:
                    if raise_on_error:
                        raise GitHubAPIError(str(e))
                    return None
                time.sleep(0.5)

            except requests.exceptions.RequestException as e:
                logger.error(f"Request failed: {e}")
                if raise_on_error:
                    raise GitHubAPIError(str(e))
                return None

        return None

    # ============================================================
    # USER / REPO
    # ============================================================

    def get_authenticated_user(self):
        """Return the authenticated user (used for token validation)."""
        return self._make_request(
            'GET', 'https://api.github.com/user', raise_on_error=True
        )

    def get_user_repos(self):
        """
        Fetch ALL repos the user has access to:
          - owned repos
          - collaborator repos
          - organization-member repos
          - public, private, and internal visibility
        Paginated, deduped.
        """
        all_repos = []
        current_page = 1
        per_page = 100
        max_pages = 20   # up to 2000 repos

        while current_page <= max_pages:
            url = (
                f"https://api.github.com/user/repos"
                f"?page={current_page}&per_page={per_page}"
                f"&sort=updated&direction=desc"
                f"&visibility=all"
                f"&affiliation=owner,collaborator,organization_member"
            )
            result = self._make_request('GET', url)
            if not isinstance(result, list):
                break

            all_repos.extend(result)
            logger.info(f"Page {current_page}: got {len(result)} repos")

            if len(result) < per_page:
                break
            current_page += 1

        # Dedupe by full_name (pagination can double-return)
        seen = set()
        unique = []
        for r in all_repos:
            key = r.get('full_name')
            if key and key not in seen:
                seen.add(key)
                unique.append(r)

        logger.info(f"Fetched {len(unique)} unique repos (raw: {len(all_repos)})")
        return unique

    def get_repo_details(self, owner, repo):
        url = f"https://api.github.com/repos/{owner}/{repo}"
        return self._make_request('GET', url)

    def get_repo_contents(self, owner, repo, path="", max_depth=2, current_depth=0):
        if current_depth >= max_depth:
            return []
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
        result = self._make_request('GET', url)
        return result if result else []

    def get_file_content(self, owner, repo, file_path):
        url = f"https://api.github.com/repos/{owner}/{repo}/contents/{file_path}"
        result = self._make_request('GET', url)
        if result and 'content' in result:
            try:
                return base64.b64decode(result['content']).decode('utf-8')
            except Exception as e:
                logger.error(f"Decode failed for {file_path}: {e}")
        return None

    # ============================================================
    # TERRAFORM DETECTION
    # ============================================================

    def has_terraform_files(self, owner, repo, github_user_id=None, max_depth=2):
        """Check if a repo contains .tf files. Cache key includes user id."""
        cache_key = f"github_terraform_{github_user_id}_{owner}_{repo}"
        cached = cache.get(cache_key)
        if cached is not None:
            return cached

        try:
            contents = self.get_repo_contents(owner, repo, max_depth=1)
            if isinstance(contents, list):
                for item in contents:
                    name = item.get('name', '').lower()
                    if name.endswith('.tf') or name.endswith('.tfvars'):
                        cache.set(cache_key, True, timeout=86400)
                        return True
                    if item.get('type') == 'dir' and name in [
                        'terraform', 'tf', 'infrastructure', 'iac',
                        'infra', 'provisioning', 'modules'
                    ]:
                        sub = self.get_repo_contents(
                            owner, repo, item.get('path', ''),
                            max_depth=2, current_depth=1
                        )
                        if isinstance(sub, list):
                            for s in sub:
                                if s.get('name', '').lower().endswith('.tf'):
                                    cache.set(cache_key, True, timeout=86400)
                                    return True

            for path in ['terraform/', 'tf/', 'infrastructure/', 'iac/',
                         'infra/', 'provisioning/', 'modules/']:
                contents = self.get_repo_contents(
                    owner, repo, path, max_depth=1, current_depth=1
                )
                if isinstance(contents, list):
                    for item in contents:
                        if item.get('name', '').lower().endswith('.tf'):
                            cache.set(cache_key, True, timeout=86400)
                            return True

            cache.set(cache_key, False, timeout=86400)
            return False

        except Exception as e:
            logger.error(f"has_terraform_files error for {owner}/{repo}: {e}")
            cache.set(cache_key, False, timeout=3600)
            return False

    # ============================================================
    # PR / DEPLOYMENTS
    # ============================================================

    def get_pull_requests(self, owner, repo, state='closed', per_page=30):
        url = (
            f"https://api.github.com/repos/{owner}/{repo}/pulls"
            f"?state={state}&per_page={per_page}"
            f"&sort=updated&direction=desc"
        )
        result = self._make_request('GET', url)
        if not result:
            return []
        merged = [p for p in result if p.get('merged_at')]
        logger.info(f"{owner}/{repo}: {len(merged)} merged of {len(result)} PRs")
        return merged

    def get_pr_files(self, owner, repo, pr_number):
        url = f"https://api.github.com/repos/{owner}/{repo}/pulls/{pr_number}/files"
        result = self._make_request('GET', url)
        return result if result else []

    def get_services_from_files(self, files_changed):
        """Determine AWS services affected — parses filename AND patch content."""
        services = set()

        name_patterns = {
            'EC2': ['ec2', 'instance', 'ami', 'key-pair', 'security-group'],
            'S3': ['s3', 'bucket'],
            'RDS': ['rds', 'database', 'postgres', 'mysql'],
            'VPC': ['vpc', 'subnet', 'nat', 'route-table'],
            'Lambda': ['lambda', 'serverless', 'function'],
            'Load Balancer': ['alb', 'elb', 'loadbalancer', 'target-group'],
            'Data Transfer': ['data', 'transfer', 'cloudfront'],
            'CloudWatch': ['cloudwatch', 'alarm', 'dashboard'],
            'IAM': ['iam', 'role', 'policy', 'user'],
            'DynamoDB': ['dynamodb', 'table'],
            'ECS': ['ecs', 'cluster', 'task-definition'],
            'EKS': ['eks', 'node-group'],
        }

        content_patterns = {
            'EC2': ['aws_instance', 'aws_launch_template', 'aws_ami', 'aws_key_pair'],
            'S3': ['aws_s3_bucket', 'aws_s3_object'],
            'RDS': ['aws_db_instance', 'aws_rds_cluster', 'aws_db_subnet_group'],
            'VPC': ['aws_vpc', 'aws_subnet', 'aws_nat_gateway', 'aws_route_table'],
            'Lambda': ['aws_lambda_function', 'aws_lambda_layer_version'],
            'Load Balancer': ['aws_lb', 'aws_alb', 'aws_elb', 'aws_lb_target_group'],
            'CloudFront': ['aws_cloudfront_distribution'],
            'CloudWatch': ['aws_cloudwatch_log_group', 'aws_cloudwatch_metric_alarm'],
            'IAM': ['aws_iam_role', 'aws_iam_policy', 'aws_iam_user'],
            'DynamoDB': ['aws_dynamodb_table'],
            'ECS': ['aws_ecs_cluster', 'aws_ecs_service', 'aws_ecs_task_definition'],
            'EKS': ['aws_eks_cluster', 'aws_eks_node_group'],
            'SNS': ['aws_sns_topic'],
            'SQS': ['aws_sqs_queue'],
            'KMS': ['aws_kms_key'],
            'Route53': ['aws_route53_zone', 'aws_route53_record'],
            'WAF': ['aws_wafv2_web_acl'],
            'Secrets Manager': ['aws_secretsmanager_secret'],
            'EFS': ['aws_efs_file_system'],
        }

        for f in files_changed:
            path = (f.get('filename') or '').lower()
            patch = (f.get('patch') or '').lower()

            for service, patterns in name_patterns.items():
                if any(p in path for p in patterns):
                    services.add(service)

            for service, patterns in content_patterns.items():
                if any(p in patch for p in patterns):
                    services.add(service)

        return sorted(services)

    # ============================================================
    # WEBHOOKS
    # ============================================================

    def create_webhook(self, owner, repo, webhook_url):
        url = f"https://api.github.com/repos/{owner}/{repo}/hooks"
        payload = {
            "name": "web",
            "active": True,
            "events": ["pull_request"],
            "config": {
                "url": webhook_url,
                "content_type": "json",
                "secret": getattr(settings, 'GITHUB_WEBHOOK_SECRET', ''),
                "insecure_ssl": "0",
            },
        }
        result = self._make_request('POST', url, json=payload)
        if result:
            logger.info(f"Webhook created for {owner}/{repo}: id={result.get('id')}")
        return result

    def delete_webhook(self, owner, repo, webhook_id):
        url = f"https://api.github.com/repos/{owner}/{repo}/hooks/{webhook_id}"
        try:
            response = self.session.delete(
                url, headers=self.headers, timeout=30, verify=_verify_tls()
            )
            response.raise_for_status()
            return True
        except Exception as e:
            logger.error(f"Delete webhook failed: {e}")
            return False


# ============================================================
# WEBHOOK SIGNATURE VERIFICATION
# ============================================================

def verify_webhook_signature(raw_body: bytes, signature_header: str) -> bool:
    """GitHub sends X-Hub-Signature-256: sha256=<hmac>. Verify it."""
    secret = getattr(settings, 'GITHUB_WEBHOOK_SECRET', '')
    if not secret:
        logger.warning("GITHUB_WEBHOOK_SECRET not set — rejecting webhook")
        return False
    if not signature_header or not signature_header.startswith('sha256='):
        return False

    expected = 'sha256=' + hmac.new(
        secret.encode('utf-8'),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(expected, signature_header)


# ============================================================
# OAUTH
# ============================================================

def exchange_code_for_token(code):
    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            url = "https://github.com/login/oauth/access_token"
            payload = {
                "client_id": settings.GITHUB_CLIENT_ID,
                "client_secret": settings.GITHUB_CLIENT_SECRET,
                "code": code,
                "redirect_uri": settings.GITHUB_REDIRECT_URL,
            }
            headers = {
                "Accept": "application/json",
                "User-Agent": "CloudManagementApp/1.0",
            }

            response = requests.post(
                url, data=payload, headers=headers,
                timeout=30, verify=_verify_tls(),
            )
            response.raise_for_status()
            data = response.json()

            if 'access_token' in data:
                return data['access_token']
            logger.error(f"Token exchange failed: {data}")
            if attempt == max_retries - 1:
                return None

        except requests.exceptions.RequestException as e:
            logger.error(f"Token exchange error (attempt {attempt+1}): {e}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
            retry_delay *= 2

    return None


def get_user_from_token(access_token):
    max_retries = 3
    retry_delay = 2

    for attempt in range(max_retries):
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "User-Agent": "CloudManagementApp/1.0",
            }
            response = requests.get(
                "https://api.github.com/user",
                headers=headers, timeout=30, verify=_verify_tls(),
            )
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.warning(f"get_user_from_token attempt {attempt+1}: {e}")
            if attempt == max_retries - 1:
                return None
            time.sleep(retry_delay)
            retry_delay *= 2

    return None


# ============================================================
# SYNC DEPLOYMENTS
# ============================================================

def sync_repo_deployments(repo_id):
    try:
        from .models import GitHubRepo, DeploymentEvent
        repo = GitHubRepo.objects.get(id=repo_id)
    except Exception as e:
        logger.error(f"sync_repo_deployments: repo {repo_id} not found: {e}")
        return

    github = GitHubService(repo.access_token)
    owner, repo_name = repo.repo_full_name.split('/')

    pulls = github.get_pull_requests(owner, repo_name, state='closed', per_page=30)

    for pr in pulls:
        pr_number = pr.get('number')
        pr_title = pr.get('title', '')
        pr_url = pr.get('html_url', '')
        merged_by = (pr.get('merged_by') or {}).get('login', 'unknown')
        merged_at = pr.get('merged_at')

        if not merged_at:
            continue

        files = github.get_pr_files(owner, repo_name, pr_number)
        services_affected = github.get_services_from_files(files)

        DeploymentEvent.objects.update_or_create(
            repo=repo,
            pr_number=pr_number,
            defaults={
                'aws_account': repo.aws_account,
                'pr_title': pr_title,
                'pr_url': pr_url,
                'merged_by': merged_by,
                'merged_at': merged_at,
                'files_changed': files[:50],
                'services_affected': services_affected,
            }
        )

    repo.last_sync_at = timezone.now()
    repo.save()