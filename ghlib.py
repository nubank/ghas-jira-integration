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