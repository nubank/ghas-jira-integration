import requests
import logging
import json
import util
import ast
from requests import HTTPError


WEBHOOK_CONFIG = """
{
    "url": "{url}",
    "content_type": "{content_type}",
    "secret": "{secret}",
    "insecure_ssl": "{insecure_ssl}",
    "events": "{envents}",
    "active": "{active}"
}
"""

RESULTS_PER_PAGE = 100

logger = logging.getLogger(__name__)


class GitHub:
    def __init__(self, url, token):
        self.url = url
        self.token = token

    def default_headers(self):
        auth = {"Authorization": "token " + self.token, "X-GitHub-Api-Version": "2022-11-28", "Accept": "application/vnd.github+json"}
#        auth.update(util.json_accept_header())
        return auth

    def getRepository(self, repo_id):
        return GHRepository(self, repo_id)

    def list_org_hooks(self, org):
        """requires a token with "admin:org_hook" permission!"""
        return self.list_hooks_helper(org)

    def list_hooks_helper(self, entity):
        if "/" in entity:
            etype = "repos"
        else:
            etype = "orgs"

        resp = requests.get(
            "{api_url}/{etype}/{ename}/hooks?per_page={results_per_page}".format(
                api_url=self.url,
                etype=etype,
                ename=entity,
                results_per_page=RESULTS_PER_PAGE,
            ),
            headers=self.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )

        while True:
            resp.raise_for_status()

            for h in resp.json():
                yield h

            nextpage = resp.links.get("next", {}).get("url", None)
            if not nextpage:
                break

            resp = requests.get(
                nextpage, headers=self.default_headers(), timeout=util.REQUEST_TIMEOUT
            )

    def create_org_hook(
        self,
        org,
        url,
        secret,
        active=True,
        events=["code_scanning_alert", "repository"],
        insecure_ssl="0",
        content_type="json",
    ):
        return self.create_hook_helper(
            org, url, secret, active, events, insecure_ssl, content_type
        )

    def create_hook_helper(
        self,
        entity,
        url,
        secret,
        active=True,
        events=["code_scanning_alert", "repository"],
        insecure_ssl="0",
        content_type="json",
    ):
        if "/" in entity:
            etype = "repos"
        else:
            etype = "orgs"

        data = json.dumps(
            {
                "config": {
                    "url": url,
                    "insecure_ssl": insecure_ssl,
                    "secret": secret,
                    "content_type": content_type,
                },
                "events": events,
                "active": active,
                "name": "web",
            }
        )
        resp = requests.post(
            "{api_url}/{etype}/{ename}/hooks".format(
                etype=etype, ename=entity, api_url=self.url
            ),
            headers=self.default_headers(),
            data=data,
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def get_team_members(self, org, team_slug):
        """Get members of a GitHub team"""
        try:
            resp = requests.get(
                f"{self.url}/orgs/{org}/teams/{team_slug}/members",
                headers=self.default_headers(),
                timeout=util.REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return resp.json()
        except HTTPError as e:
            logger.error(f"Failed to get team members for {team_slug}: {e}")
            return []

    def get_team_members_with_roles(self, org, team_slug):
        """Get members of a GitHub team with their roles (maintainer/member)"""
        try:
            resp = requests.get(
                f"{self.url}/orgs/{org}/teams/{team_slug}/members?role=all",
                headers=self.default_headers(),
                timeout=util.REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            members = resp.json()
            
            # Get detailed role information for each member
            members_with_roles = []
            for member in members:
                try:
                    # Get membership details to determine role
                    membership_resp = requests.get(
                        f"{self.url}/orgs/{org}/teams/{team_slug}/memberships/{member['login']}",
                        headers=self.default_headers(),
                        timeout=util.REQUEST_TIMEOUT
                    )
                    membership_resp.raise_for_status()
                    membership_data = membership_resp.json()
                    
                    member_info = {
                        'login': member['login'],
                        'role': membership_data.get('role', 'member')  # 'maintainer' or 'member'
                    }
                    members_with_roles.append(member_info)
                except HTTPError as e:
                    logger.warning(f"Failed to get role for member {member['login']} in team {team_slug}: {e}")
                    # Default to member role if we can't get the specific role
                    member_info = {
                        'login': member['login'],
                        'role': 'member'
                    }
                    members_with_roles.append(member_info)
            
            return members_with_roles
        except HTTPError as e:
            logger.error(f"Failed to get team members with roles for {team_slug}: {e}")
            return []

    def get_user_details(self, username):
        try:
            resp = requests.get(
                f"{self.url}/users/{username}",
                headers=self.default_headers(),
                timeout=util.REQUEST_TIMEOUT
            )
            resp.raise_for_status()
            return resp.json()
        except HTTPError as e:
            logger.error(f"Failed to get user details for {username}: {e}")
            return None

class GHRepository:
    def __init__(self, github, repo_id):
        self.gh = github
        self.repo_id = repo_id

    def list_hooks(self):
        return self.gh.list_hooks_helper(self.repo_id)

    def create_hook(
        self,
        url,
        secret,
        active=True,
        events=["code_scanning_alert", "repository"],
        insecure_ssl="0",
        content_type="json",
    ):
        return self.gh.create_hook_helper(
            self.repo_id, url, secret, active, events, insecure_ssl, content_type
        )

    def get_key(self):
        return util.make_key(self.repo_id)

    def alerts_helper(self, api_segment, state=None):
        if state:
            state = "&state=" + state
        else:
            state = ""

        try:
            resp = requests.get(
                "{api_url}/repos/{repo_id}/{api_segment}/alerts?per_page={results_per_page}{state}".format(
                    api_url=self.gh.url,
                    repo_id=self.repo_id,
                    api_segment=api_segment,
                    state=state,
                    results_per_page=RESULTS_PER_PAGE,
                ),
                headers=self.gh.default_headers(),
                timeout=util.REQUEST_TIMEOUT,
            )

            while True:
                resp.raise_for_status()

                for a in resp.json():
                    yield a

                nextpage = resp.links.get("next", {}).get("url", None)
                if not nextpage:
                    break

                resp = requests.get(
                    nextpage,
                    headers=self.gh.default_headers(),
                    timeout=util.REQUEST_TIMEOUT,
                )

        except HTTPError as httpe:
            if httpe.response.status_code == 404:
                # A 404 suggests that the repository doesn't exist
                # so we return an empty list
                pass
            else:
                # propagate everything else
                raise

    def get_info(self):
        resp = requests.get(
            "{api_url}/repos/{repo_id}".format(
                api_url=self.gh.url, repo_id=self.repo_id
            ),
            headers=self.gh.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        return resp.json()

    def fetch_codeowners(self):
        codeowners_paths = [
            ".github/CODEOWNERS"
        ]
        
        for path in codeowners_paths:
            try:
                resp = requests.get(
                    f"{self.gh.url}/repos/{self.repo_id}/contents/{path}",
                    headers=self.gh.default_headers(),
                    timeout=util.REQUEST_TIMEOUT
                )
                resp.raise_for_status()
                
                content = resp.json().get('content')
                if content:
                    import base64
                    return base64.b64decode(content).decode('utf-8')
                    
            except HTTPError as e:
                if e.response.status_code == 404:
                    continue
                raise
                
        return None

    def calculate_pattern_score(self, file_path, pattern, owners_list):
        file_path = file_path.strip('/').split('/')
        pattern = pattern.strip('/').split('/')
        score = 0
        consecutive_matches = 0
        original_pattern = pattern


        for i, pattern_part in enumerate(pattern):
            if pattern_part == '*':
                score -= 10  # Penalidade para curinga simples
                continue
            if pattern_part == '**':
                score -= 20  # Penalidade maior para curinga duplo
                continue
            if i >= len(file_path):
                return pattern, -float('inf') # Penalidade máxima se o padrão for mais longo que o caminho do arquivo

            position_multiplier = (i + 1)

            if pattern_part == file_path[i]:
                score += 40 * position_multiplier
                consecutive_matches += 1
            else:
                # Penalidade se a parte do padrão não corresponder à parte do caminho do arquivo
                score -= 20 * position_multiplier
                consecutive_matches = 0 # Reset consecutive matches if there is a mismatch

            score += consecutive_matches * 50  # Bônus para correspondências consecutivas

        # Verificação adicional para padrões terminando com curinga (adicionado aqui)
        last_pattern_part = pattern[-1]
        if last_pattern_part in ('*', '**'):
            if last_pattern_part == '*':
                # Verifique se a última parte do caminho do arquivo contém a penúltima parte do padrão
                if len(pattern) > 1 and len(file_path) > len(pattern) - 2 and pattern[-2] not in file_path[-1]:
                    score -= 50  # Penalidade se a última parte do padrão não corresponder à parte do caminho do arquivo
            # Lógica semelhante para '**' pode ser adicionada aqui se necessário


        return original_pattern, score

    def parse_codeowners_for_path(self, file_path):
        content = self.fetch_codeowners()
        if not content:
            return []
            
        all_scores_from_each_line = dict()

        for line in content.splitlines():
            line = line.strip()

            if not line or line.startswith('#'):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue
                
            pattern = parts[0]
            owners = parts[1:]
            
            pattern, full_score_linha = self.calculate_pattern_score(file_path, pattern, owners)
            
            pattern = tuple(pattern)
            all_scores_from_each_line[pattern] = {
                "score": full_score_linha,
                "owners": owners
            }

        if not all_scores_from_each_line:
            return []

        sorted_scores = sorted(all_scores_from_each_line.items(), key=lambda x: x[1]['score'], reverse=True)    
        owners = sorted_scores[0][1]['owners']
        return owners

    def isprivate(self):
        return self.get_info()["private"]

    def get_alerts(self, state=None):
        for a in self.alerts_helper("code-scanning", state):
            yield Alert(self, a)

    def get_secrets(self, state=None):
        # secret scanning alerts are only accessible on private repositories, so
        # we return an empty list on public ones
        if not self.isprivate():
            return
        for a in self.alerts_helper("secret-scanning", state):
            yield Secret(self, a)

    def get_alert(self, alert_num):
        resp = requests.get(
            "{api_url}/repos/{repo_id}/code-scanning/alerts/{alert_num}".format(
                api_url=self.gh.url, repo_id=self.repo_id, alert_num=alert_num
            ),
            headers=self.gh.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )
        try:
            resp.raise_for_status()
            return Alert(self, resp.json())
        except HTTPError as httpe:
            if httpe.response.status_code == 404:
                # A 404 suggests that the alert doesn't exist
                return None
            else:
                # propagate everything else
                raise         

class AlertBase:
    def __init__(self, github_repo, json):
        self.github_repo = github_repo
        self.gh = github_repo.gh
        self.json = json

    def get_state(self):
        return self.json["state"] == "open"

    def get_type(self):
        return type(self).__name__

    def number(self):
        return int(self.json["number"])

    def short_desc(self):
        raise NotImplementedError

    def long_desc(self):
        raise NotImplementedError

    def hyperlink(self):
        return self.json["html_url"]

    def can_transition(self):
        return True

    def get_key(self):
        raise NotImplementedError

    def adjust_state(self, target_state):
        if self.get_state() == target_state:
            return

        logger.info(
            '{action} {atype} {alert_num} of repository "{repo_id}".'.format(
                atype=self.get_type(),
                action="Reopening" if target_state else "Closing",
                alert_num=self.number(),
                repo_id=self.github_repo.repo_id,
            )
        )
        self.do_adjust_state(target_state)

    def get_tool_name(self):
        tool_name = self.json.get("tool", {}).get("name", "")
        if not tool_name:
            return
        return tool_name

    def get_location(self):
        location = self.json.get("most_recent_instance", {}).get("location", {}).get("path", "")
        if not location:
            return
        return location    

    def get_responsible_teams(self):
        file_path = self.get_location()
        if not file_path:
            return []
            
        teams = self.github_repo.parse_codeowners_for_path(file_path)
        
        if not teams:  
            return "mmr-team"

        cleaned_teams = [
            team.replace('@nubank/', '') 
            for team in teams
        ]
        
        return ", ".join(cleaned_teams) if cleaned_teams else ""
    
    def get_severity(self):
        security_severity_level = self.json.get("rule", {}).get("security_severity_level", "")
        if not security_severity_level:
            security_severity_level = self.json.get("severity", "")
        return security_severity_level

    def get_full_description(self):
        return

    def get_identification_date(self):
        identification_date = self.json.get("created_at", "")
        if not identification_date:
            return
        return identification_date

    def get_language(self):
        environment_str = self.json.get("most_recent_instance", {}).get("environment", "{}")
        environment = json.loads(environment_str)
        if environment is not None and isinstance(environment, dict):
            language = environment.get("language", "")
            if not language:
                return []
            return [language]
        return []

    def get_cwe(self):
        return None

    def get_team_members(self):
        teams = self.get_responsible_teams()
        if not teams:
            return []
            
        org = self.github_repo.repo_id.split('/')[0]
        
        member_logins = []
        for team in teams.split(', '):
            members = self.gh.get_team_members(org, team)
            logins = [member.get('login') for member in members if member.get('login')]
            member_logins.extend(logins)
        
        return member_logins

    def get_team_members_with_roles(self):
        """Get team members organized by role (maintainers first, then members)"""
        teams = self.get_responsible_teams()
        if not teams:
            return {'maintainers': [], 'members': []}
            
        org = self.github_repo.repo_id.split('/')[0]
        
        maintainers = []
        members = []
        
        for team in teams.split(', '):
            team_members = self.gh.get_team_members_with_roles(org, team)
            for member in team_members:
                login = member.get('login')
                role = member.get('role', 'member')
                
                if login:
                    if role == 'maintainer':
                        if login not in maintainers:
                            maintainers.append(login)
                    else:
                        if login not in members:
                            members.append(login)
        
        return {'maintainers': maintainers, 'members': members}

    def get_valid_assignees(self):
        """Get valid assignees with maintainers prioritized first"""
        team_members = self.get_team_members_with_roles()
        maintainers = team_members.get('maintainers', [])
        members = team_members.get('members', [])
        
        # Prioritize maintainers first, then regular members
        prioritized_logins = maintainers + members
        
        valid_assignees = []
        
        for login in prioritized_logins:
            user_details = self.gh.get_user_details(login)
            if user_details and user_details.get('name'):
                valid_assignees.append(user_details['name'])
                
        return valid_assignees

    def get_prioritized_assignees(self):
        """Get assignees separated by role for more granular assignment logic"""
        team_members = self.get_team_members_with_roles()
        maintainers = team_members.get('maintainers', [])
        members = team_members.get('members', [])
        
        valid_maintainers = []
        valid_members = []
        
        # Process maintainers first
        for login in maintainers:
            user_details = self.gh.get_user_details(login)
            if user_details and user_details.get('name'):
                valid_maintainers.append(user_details['name'])
        
        # Process regular members
        for login in members:
            user_details = self.gh.get_user_details(login)
            if user_details and user_details.get('name'):
                valid_members.append(user_details['name'])
                
        return {'maintainers': valid_maintainers, 'members': valid_members}

    def get_cve(self):
        cve = self.json.get("rule", {}).get("id", "")
        if not cve:
            return None
        
        cve = cve.replace(" ", "-")
        
        if cve.upper().startswith("CVE-"):
            return cve
        else:
            return None

class Alert(AlertBase):
    def __init__(self, github_repo, json):
        AlertBase.__init__(self, github_repo, json)

    def can_transition(self):
        return self.json["state"] != "fixed"

    def long_desc(self):
        return self.json["rule"]["description"]

    def short_desc(self):
        return self.json["rule"]["id"]

    def get_key(self):
        return util.make_key(self.github_repo.repo_id + "/" + str(self.number()))

    def do_adjust_state(self, target_state):
        state = "open"
        reason = ""
        if not target_state:
            state = "dismissed"
            reason = ', "dismissed_reason": "won\'t fix"'
        data = '{{"state": "{state}"{reason}}}'.format(state=state, reason=reason)
        resp = requests.patch(
            "{api_url}/repos/{repo_id}/code-scanning/alerts/{alert_num}".format(
                api_url=self.gh.url,
                repo_id=self.github_repo.repo_id,
                alert_num=self.number(),
            ),
            data=data,
            headers=self.gh.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

    def get_full_description(self):
        rule = self.json.get("rule", {})
        
        # Get description sections
        full_desc = rule.get("full_description", "").strip()
        help_text = rule.get("help", "")
        
        if not help_text:
            return full_desc
            
        # Process help text sections
        sections = {}
        current_section = None
        current_content = []
        
        for line in help_text.split('\n'):
            line = line.strip()
            if not line:
                continue
                
            if line.startswith('# '):  # Main header
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = "Details"  # Changed from "Description" to "Details"
                current_content = [line.replace('# ', '')]
            elif line.startswith('## '):  # Subheader
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = line.replace('## ', '').strip()
                current_content = []
                # Skip References section
                if current_section == 'References':
                    current_section = None
                    current_content = []
            else:
                if current_section and current_section != 'References':
                    current_content.append(line)
        
        # Add final section if not References
        if current_section and current_section != 'References' and current_content:
            sections[current_section] = '\n'.join(current_content).strip()
        
        # Format output with desired section order
        formatted_sections = []
        if full_desc:
            formatted_sections.append(full_desc)
        
        section_order = ['Details', 'Recommendation', 'Example']  # Changed from "Description" to "Details"
        for section in section_order:
            if section in sections:
                formatted_sections.append(f"*{section}*\n{sections[section]}")
        
        return '\n\n'.join(formatted_sections)

    def get_cwe(self):
        tags = self.json.get("rule", {}).get("tags", [])
        cwe_list = []
        for tag in tags:
            if tag.startswith("external/cwe/"):
                cwe = tag.replace("external/cwe/", "")
                cwe_list.append(cwe)
        if not cwe_list:
            return
        return cwe_list
    
class Secret(AlertBase):
    def __init__(self, github_repo, json):
        AlertBase.__init__(self, github_repo, json)

    def can_transition(self):
        return True

    def long_desc(self):
        return self.json["secret_type"]

    def short_desc(self):
        return self.long_desc()

    def get_key(self):
        return util.make_key(
            self.github_repo.repo_id + "/" + self.get_type() + "/" + str(self.number())
        )

    def get_location(self):
        locations = self.fetch_locations()
        if locations and len(locations) > 0:
            return locations[0].get("details", {}).get("path", None)
        return None

    def do_adjust_state(self, target_state):
        state = "open"
        resolution = ""
        if not target_state:
            state = "resolved"
            resolution = ', "resolution": "wont_fix"'
        data = '{{"state": "{state}"{resolution}}}'.format(
            state=state, resolution=resolution
        )
        resp = requests.patch(
            "{api_url}/repos/{repo_id}/secret-scanning/alerts/{alert_num}".format(
                api_url=self.gh.url,
                repo_id=self.github_repo.repo_id,
                alert_num=self.number(),
            ),
            data=data,
            headers=self.gh.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
    
    def get_full_description(self):
        return None
    
    def get_cwe(self):
        return None
    
    def get_tool_name(self):
        return "GitHub - Secret Scanning"
    
    def fetch_locations(self):
        try:
            resp = requests.get(
                "{api_url}/repos/{repo_id}/secret-scanning/alerts/{alert_num}/locations".format(
                    api_url=self.gh.url,
                    repo_id=self.github_repo.repo_id,
                    alert_num=self.number(),
                ),
                headers=self.gh.default_headers(),
                timeout=util.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to fetch locations for secret alert {self.number()} in {self.github_repo.repo_id}: {e}")
            return []

    def get_secret_line_numbers(self):
        """Get the line numbers where the secret is located"""
        locations = self.fetch_locations()
        line_numbers = []
        
        for location in locations:
            details = location.get("details", {})
            start_line = details.get("start_line")
            end_line = details.get("end_line")
            
            if start_line is not None:
                if end_line is not None and end_line != start_line:
                    # Multi-line secret, get all lines
                    line_numbers.extend(range(start_line, end_line + 1))
                else:
                    # Single line secret
                    line_numbers.append(start_line)
        
        return list(set(line_numbers))  # Remove duplicates

    def get_secret_commit_sha(self):
        """Get the commit SHA where the secret was found (if available)"""
        locations = self.fetch_locations()
        
        logger.debug(f"Alert {self.number()}: Checking {len(locations)} locations for commit SHA")
        
        for i, location in enumerate(locations):
            logger.debug(f"Location {i}: {location}")
            
            # Check if the location contains commit information
            details = location.get("details", {})
            commit_sha = details.get("commit_sha")
            if commit_sha:
                logger.debug(f"Found commit_sha in location {i}: {commit_sha}")
                return commit_sha
            
            # Alternative: check for blob_sha and try to find corresponding commit
            blob_sha = details.get("blob_sha")
            if blob_sha:
                logger.debug(f"Found blob_sha in location {i}: {blob_sha}")
                # We could potentially find the commit that contains this blob
                # but this is more complex and may not be reliable
        
        logger.debug(f"No commit SHA found in any location for alert {self.number()}")
        return None

    def get_secret_author(self):
        """Get the GitHub user who most likely introduced the secret using git blame analysis"""
        # Import here to avoid circular imports
        import sync
        
        alert_num = self.number()
        logger.info(f"Starting secret author detection for alert {alert_num}")
        
        # Check if feature is enabled
        if not sync.ASSIGN_TO_SECRET_AUTHOR:
            logger.info(f"Secret author assignment disabled for alert {alert_num} (ASSIGN_TO_SECRET_AUTHOR=false) - skipping git blame analysis")
            return None
            
        file_path = self.get_location()
        if not file_path:
            logger.warning(f"No file path found for secret alert {alert_num} - cannot determine author")
            return None
            
        line_numbers = self.get_secret_line_numbers()
        if not line_numbers:
            logger.warning(f"No line numbers found for secret alert {alert_num} in file {file_path}")
            return None
            
        logger.info(f"Secret alert {alert_num} found in {file_path} at lines: {line_numbers}")
        
        # Check if we have specific commit information from the alert
        secret_commit_sha = self.get_secret_commit_sha()
        if secret_commit_sha:
            logger.info(f"Secret alert {alert_num} includes commit SHA: {secret_commit_sha}")
        else:
            logger.info(f"No commit SHA found in alert {alert_num} locations")
        
        try:
            # Use true git blame analysis to find who last modified the secret lines
            logger.info(f"Attempting git blame analysis for alert {alert_num}")
            secret_author = self.get_line_blame_author(file_path, line_numbers, secret_commit_sha)
            
            if secret_author:
                logger.info(f"SUCCESS: Found secret author via git blame for alert {alert_num}: {secret_author}")
                return secret_author
            
            # Fallback to commit history analysis if blame fails
            logger.warning(f"Git blame failed (file may have been deleted or moved), falling back to commit history analysis for alert {alert_num}")
            
            # If we have the specific commit SHA, try to get the commit directly
            if secret_commit_sha:
                logger.info(f"Using commit SHA from alert: {secret_commit_sha}")
                secret_commit = self.get_commit_details(secret_commit_sha)
                if secret_commit:
                    logger.info(f"Successfully retrieved commit details for {secret_commit_sha}")
                    
                    # Verify this commit actually touches the file we're interested in
                    files_in_commit = secret_commit.get("files", [])
                    file_found = any(f.get("filename") == file_path for f in files_in_commit)
                    if file_found:
                        logger.info(f"Confirmed: Commit {secret_commit_sha} contains changes to {file_path}")
                    else:
                        logger.warning(f"Commit {secret_commit_sha} does not contain changes to {file_path}")
                        # Still use this commit as it might be the commit where the secret was detected
                else:
                    logger.warning(f"Could not retrieve commit details for {secret_commit_sha}")
            else:
                secret_commit = None
            
            # If that didn't work, fall back to general commit history
            if not secret_commit:
                commits = self.get_file_commit_history(file_path, limit=50)
                
                if not commits:
                    logger.warning(f"No commit history found for file {file_path} in alert {alert_num}")
                    return None
                    
                secret_commit = self.find_secret_introduction_commit(commits, file_path, line_numbers, secret_commit_sha)
            
            if secret_commit:
                author_login = secret_commit.get("author", {}).get("login")
                if author_login:
                    user_details = self.gh.get_user_details(author_login)
                    if user_details and user_details.get("name"):
                        logger.info(f"FALLBACK SUCCESS: Found secret author via commit history for alert {alert_num}: {user_details['name']} ({author_login})")
                        return user_details["name"]
                        
            logger.error(f"FAILED: Could not determine secret author for alert {alert_num} via any method")
            return None
            
        except Exception as e:
            logger.error(f"ERROR: Exception while finding secret author for alert {alert_num}: {e}")
            return None

    def get_file_commit_history(self, file_path, limit=50):
        """Get commit history for a specific file"""
        try:
            resp = requests.get(
                "{api_url}/repos/{repo_id}/commits".format(
                    api_url=self.gh.url,
                    repo_id=self.github_repo.repo_id
                ),
                params={
                    "path": file_path,
                    "per_page": limit
                },
                headers=self.gh.default_headers(),
                timeout=util.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            logger.error(f"Failed to get commit history for {file_path}: {e}")
            return []

    def find_secret_introduction_commit(self, commits, file_path, line_numbers, secret_commit_sha=None):
        """Find the commit that most likely introduced the secret"""
        if not commits:
            return None
            
        # If we have the specific commit SHA from the alert, try to find it first
        if secret_commit_sha:
            for commit in commits:
                if commit.get("sha") == secret_commit_sha:
                    logger.info(f"Found exact commit from alert: {secret_commit_sha}")
                    return commit
                    
            # If the specific commit isn't in our list, try to get it directly
            logger.info(f"Specific commit {secret_commit_sha} not in file history, fetching directly")
            specific_commit = self.get_commit_details(secret_commit_sha)
            if specific_commit:
                return specific_commit
            
        # Strategy: Look for commits that added content around the secret lines
        # We'll check the most recent commits first, as they're more likely to be relevant
        for commit in commits[:10]:  # Check up to 10 most recent commits
            try:
                commit_sha = commit.get("sha")
                if not commit_sha:
                    continue
                    
                # Get the commit details to see what changed
                commit_details = self.get_commit_details(commit_sha)
                if not commit_details:
                    continue
                    
                # Check if this commit modified lines near where the secret was found
                if self.commit_affects_secret_lines(commit_details, file_path, line_numbers):
                    logger.debug(f"Found potential secret introduction commit: {commit_sha}")
                    return commit
                    
            except Exception as e:
                logger.warning(f"Error analyzing commit {commit.get('sha', 'unknown')}: {e}")
                continue
                
            # If no specific commit found, return the most recent commit as fallback
            if commits:
                logger.debug(f"Using most recent commit as fallback for secret author")
                return commits[0]
                
            return None

    def get_commit_details(self, commit_sha):
        """Get detailed information about a specific commit"""
        try:
            url = "{api_url}/repos/{repo_id}/commits/{commit_sha}".format(
                api_url=self.gh.url,
                repo_id=self.github_repo.repo_id,
                commit_sha=commit_sha
            )
            logger.debug(f"Fetching commit details from: {url}")
            
            resp = requests.get(
                url,
                headers=self.gh.default_headers(),
                timeout=util.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            
            commit_data = resp.json()
            logger.debug(f"Successfully fetched commit {commit_sha} by {commit_data.get('author', {}).get('login', 'unknown')}")
            return commit_data
            
        except Exception as e:
            logger.warning(f"Failed to get commit details for {commit_sha}: {e}")
            return None

    def commit_affects_secret_lines(self, commit_details, file_path, line_numbers):
        """Check if a commit affects the lines where the secret was found"""
        try:
            files = commit_details.get("files", [])
            
            for file_info in files:
                if file_info.get("filename") == file_path:
                    # Check if the file was added or modified (not just deleted)
                    status = file_info.get("status", "")
                    if status in ["added", "modified"]:
                        # For simplicity, we'll consider any addition/modification as potentially relevant
                        # In a more sophisticated implementation, we could parse the patch
                        # to see if it affects the specific line numbers
                        return True
                        
            return False
            
        except Exception as e:
            logger.warning(f"Error checking if commit affects secret lines: {e}")
            return False

    def get_prioritized_assignees(self):
        """Override to prioritize secret author when feature is enabled"""
        # Import here to avoid circular imports
        import sync
        
        alert_num = self.number()
        logger.info(f"Determining assignee for secret alert {alert_num}")
        
        if sync.ASSIGN_TO_SECRET_AUTHOR:
            logger.info(f"Secret author assignment enabled - attempting to find author for alert {alert_num}")
            secret_author = self.get_secret_author()
            
            if secret_author:
                logger.info(f"ASSIGNMENT SUCCESS: Prioritizing secret author '{secret_author}' for alert {alert_num}")
                return {'maintainers': [secret_author], 'members': []}
            else:
                logger.warning(f"Secret author not found for alert {alert_num}, falling back to CODEOWNERS")
        else:
            logger.info(f"Secret author assignment disabled for alert {alert_num} (ASSIGN_TO_SECRET_AUTHOR=false), using CODEOWNERS")
        
        # Fall back to standard CODEOWNERS-based assignment
        logger.info(f"Using CODEOWNERS-based assignment for alert {alert_num}")
        codeowners_result = super().get_prioritized_assignees()
        
        if codeowners_result and (codeowners_result.get('maintainers') or codeowners_result.get('members')):
            maintainers = codeowners_result.get('maintainers', [])
            members = codeowners_result.get('members', [])
            total_assignees = len(maintainers) + len(members)
            logger.info(f"CODEOWNERS SUCCESS: Found {total_assignees} potential assignees for alert {alert_num} (maintainers: {len(maintainers)}, members: {len(members)})")
            if maintainers:
                logger.info(f"CODEOWNERS maintainers for alert {alert_num}: {maintainers}")
            if members:
                logger.info(f"CODEOWNERS members for alert {alert_num}: {members}")
                
            # Log the primary assignee that will be tried first
            primary_assignee = maintainers[0] if maintainers else (members[0] if members else None)
            if primary_assignee:
                logger.info(f"PRIMARY ASSIGNEE for alert {alert_num}: {primary_assignee} (from CODEOWNERS)")
        else:
            logger.warning(f"No CODEOWNERS found for alert {alert_num}, will use default assignment")
        
        return codeowners_result

    def get_line_blame_author(self, file_path, line_numbers, secret_commit_sha=None):
        """Get the author who last modified the specific lines using git blame analysis"""
        try:
            # First try to get the current file content
            file_content = self.get_file_content(file_path)
            
            # If file doesn't exist in current branch, try to find it in commit history
            if not file_content:
                logger.info(f"File {file_path} not found in current branch, searching in commit history")
                
                # First, try with the specific commit SHA from the alert if we have it
                if secret_commit_sha:
                    logger.info(f"Trying to get {file_path} from alert commit SHA: {secret_commit_sha}")
                    file_content = self.get_file_content(file_path, secret_commit_sha)
                    if file_content:
                        logger.info(f"Successfully found {file_path} in alert commit {secret_commit_sha}")
                    else:
                        logger.warning(f"Could not get {file_path} from alert commit {secret_commit_sha}")
                
                # If that didn't work, try the general commit history approach
                if not file_content:
                    commits = self.get_file_commit_history(file_path, limit=50)
                    
                    if commits:
                        # Try to get file content from the most recent commit where it existed
                        for commit in commits[:10]:  # Check up to 10 recent commits
                            commit_sha = commit.get("sha")
                            if commit_sha:
                                file_content = self.get_file_content(file_path, commit_sha)
                                if file_content:
                                    logger.info(f"Found {file_path} in commit {commit_sha}, proceeding with blame analysis")
                                    break
                
                if not file_content:
                    logger.debug(f"Could not get file content for {file_path} from any commit")
                    return None
            
            # Get commit history for detailed analysis
            commits = self.get_file_commit_history(file_path, limit=100)
            if not commits:
                logger.debug(f"No commit history found for {file_path}")
                return None
            
            # Analyze each line to find who last modified it
            line_authors = {}
            
            for line_num in line_numbers:
                author = self.find_line_last_author(file_path, line_num, commits)
                if author:
                    line_authors[line_num] = author
            
            if not line_authors:
                logger.debug(f"No line authors found for lines {line_numbers} in {file_path}")
                return None
            
            # Find the most frequent author (in case secret spans multiple lines with different authors)
            author_counts = {}
            for author in line_authors.values():
                author_counts[author] = author_counts.get(author, 0) + 1
            
            # Return the author who modified the most lines containing the secret
            most_frequent_author = max(author_counts.items(), key=lambda x: x[1])[0]
            
            # Get full user details
            user_details = self.gh.get_user_details(most_frequent_author)
            if user_details and user_details.get("name"):
                logger.debug(f"Git blame found author {user_details['name']} ({most_frequent_author}) for lines {line_numbers}")
                return user_details["name"]
                
            return None
            
        except Exception as e:
            logger.warning(f"Git blame analysis failed for {file_path}: {e}")
            return None

    def get_file_content(self, file_path, commit_sha=None):
        """Get the content of a file, optionally from a specific commit"""
        try:
            # Try to get from specific commit first if provided
            if commit_sha:
                logger.info(f"Attempting to get {file_path} content from commit {commit_sha}")
                resp = requests.get(
                    "{api_url}/repos/{repo_id}/contents/{file_path}".format(
                        api_url=self.gh.url,
                        repo_id=self.github_repo.repo_id,
                        file_path=file_path
                    ),
                    params={"ref": commit_sha},
                    headers=self.gh.default_headers(),
                    timeout=util.REQUEST_TIMEOUT,
                )
                
                if resp.status_code == 200:
                    content_data = resp.json()
                    if content_data.get("type") == "file" and content_data.get("content"):
                        import base64
                        content = base64.b64decode(content_data["content"]).decode('utf-8')
                        logger.info(f"Successfully retrieved {file_path} from commit {commit_sha}")
                        return content.split('\n')
                else:
                    logger.warning(f"File {file_path} not found in commit {commit_sha}: {resp.status_code}")
            
            # Fall back to current branch
            logger.info(f"Attempting to get {file_path} content from current branch")
            resp = requests.get(
                "{api_url}/repos/{repo_id}/contents/{file_path}".format(
                    api_url=self.gh.url,
                    repo_id=self.github_repo.repo_id,
                    file_path=file_path
                ),
                headers=self.gh.default_headers(),
                timeout=util.REQUEST_TIMEOUT,
            )
            resp.raise_for_status()
            
            content_data = resp.json()
            if content_data.get("type") == "file" and content_data.get("content"):
                import base64
                content = base64.b64decode(content_data["content"]).decode('utf-8')
                logger.info(f"Successfully retrieved {file_path} from current branch")
                return content.split('\n')
            
            return None
            
        except Exception as e:
            if "404" in str(e):
                logger.warning(f"File {file_path} not found (404) - may have been deleted after secret was introduced")
            else:
                logger.warning(f"Failed to get file content for {file_path}: {e}")
            return None

    def find_line_last_author(self, file_path, line_number, commits):
        """Find who last modified a specific line by analyzing commit diffs"""
        try:
            # Go through commits from most recent to oldest
            for commit in commits:
                commit_sha = commit.get("sha")
                if not commit_sha:
                    continue
                
                # Get commit details with diff information
                commit_details = self.get_commit_details(commit_sha)
                if not commit_details:
                    continue
                
                # Check if this commit modified the line we're interested in
                if self.commit_modified_line(commit_details, file_path, line_number):
                    author_login = commit.get("author", {}).get("login")
                    if author_login:
                        logger.debug(f"Found line {line_number} last modified by {author_login} in commit {commit_sha}")
                        return author_login
            
            # If no specific commit found, return the author of the first commit to the file
            if commits:
                author_login = commits[-1].get("author", {}).get("login")  # Last commit = oldest commit
                if author_login:
                    logger.debug(f"Using file creator {author_login} as fallback for line {line_number}")
                    return author_login
            
            return None
            
        except Exception as e:
            logger.warning(f"Error finding author for line {line_number}: {e}")
            return None

    def commit_modified_line(self, commit_details, file_path, line_number):
        """Check if a commit modified a specific line (simplified implementation)"""
        try:
            files = commit_details.get("files", [])
            
            for file_info in files:
                if file_info.get("filename") == file_path:
                    # Get the patch to analyze line changes
                    patch = file_info.get("patch", "")
                    if not patch:
                        continue
                    
                    # Parse the patch to see if it affects our line
                    # This is a simplified implementation - a full implementation
                    # would need to parse unified diff format properly
                    if self.patch_affects_line(patch, line_number):
                        return True
            
            return False
            
        except Exception as e:
            logger.warning(f"Error checking if commit modified line {line_number}: {e}")
            return False

    def patch_affects_line(self, patch, target_line):
        """Simplified patch analysis to check if a specific line was modified"""
        try:
            lines = patch.split('\n')
            current_line = 0
            
            for line in lines:
                if line.startswith('@@'):
                    # Parse hunk header: @@ -old_start,old_count +new_start,new_count @@
                    import re
                    match = re.search(r'@@\s*-\d+(?:,\d+)?\s*\+(\d+)(?:,\d+)?\s*@@', line)
                    if match:
                        current_line = int(match.group(1)) - 1  # Convert to 0-based
                elif line.startswith('+') and not line.startswith('+++'):
                    # This is an added line
                    current_line += 1
                    if current_line == target_line:
                        return True
                elif line.startswith('-') and not line.startswith('---'):
                    # This is a deleted line - doesn't increment current_line
                    pass
                elif not line.startswith('\\'):
                    # This is a context line (unchanged)
                    current_line += 1
            
            return False
            
        except Exception as e:
            logger.warning(f"Error parsing patch for line {target_line}: {e}")
            return False    
