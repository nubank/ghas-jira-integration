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

    def get_dependabot_alerts(self, state=None):
        """Fetch Dependabot alerts similar to how we fetch code scanning alerts"""
        for a in self.alerts_helper("dependabot", state):
            yield DependabotAlert(self, a)

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
        
        # Clean team names by removing organization prefix
        cleaned_teams = [
            team.replace('@nubank/', '') 
            for team in teams
        ]
        
        # Join team names with comma and space
        return ", ".join(cleaned_teams) if cleaned_teams else ""
    
    def get_severity(self):
        security_severity_level = self.json.get("rule", {}).get("security_severity_level", "")
        if not security_severity_level:
            security_severity_level = self.json.get("severity", "")
        return security_severity_level

#    def get_full_description(self):
#        return

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

    def get_package_info(self):
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

    def location(self):
        return ''

    def get_package_info(self):
        return None

    def get_full_description(self):
        rule = self.json.get("rule", {})
        
        # Get description sections
        full_desc = rule.get("full_description", "").strip()
        help_text = rule.get("help", "")
        
        if not help_text:
            return full_desc
            
        # Process help text sections
        sections = []
        current_section = []
        
        for line in help_text.split('\n'):
            line = line.strip()
            if not line:
                continue
            if line.startswith('#'):
                if current_section:
                    sections.append('\n'.join(current_section))
                    current_section = []
                continue
            current_section.append(line)
            
        if current_section:
            sections.append('\n'.join(current_section))
            
        return f"{full_desc}\n\n{'\n\n'.join(sections)}"

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

    def location(self):
        return ''

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

    def get_package_info(self):
        return None        

    def get_full_description(self):
        return None
    
    def get_cwe(self):
        return None
    
    def get_tool_name(self):
        return "GitHub - Secret Scanning"

class DependabotAlert(AlertBase):
    def __init__(self, github_repo, json):
        AlertBase.__init__(self, github_repo, json)

    def get_type(self):
        return "Dependabot"     

    def can_transition(self):
        return True

    def long_desc(self):
        return f"{self.json.get('security_advisory', {}).get('summary', '')}"

    def short_desc(self):
        return f"Dependency: {self.json.get('dependency', {}).get('package', {}).get('name', '')}"

    def get_key(self):
        return util.make_key(
            self.github_repo.repo_id + "/dependabot/" + str(self.number())
        )

    def get_severity(self):
        return self.json.get("security_advisory", {}).get("severity", "")

    def get_state(self):
        return self.json.get("state") == "open"

    def get_location(self):
        return self.json.get("dependency", {}).get("manifest_path", "")

    def do_adjust_state(self, target_state):
        state = "open" if target_state else "dismissed"
        data = json.dumps({"state": state})
        
        resp = requests.patch(
            f"{self.gh.url}/repos/{self.github_repo.repo_id}/dependabot/alerts/{self.number()}",
            data=data,
            headers=self.gh.default_headers(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

    def location(self):
        manifest_path = self.json.get("dependency", {}).get("manifest_path", "")
        if not manifest_path:
            return
        return manifest_path

    def get_package_info(self):
        security_vuln = self.json.get("security_vulnerability", {})
        package = security_vuln.get("package", {})
        
        name = package.get('name', 'Unknown')
        ecosystem = package.get('ecosystem', 'Unknown')
        current_version = security_vuln.get('vulnerable_version_range', 'Unknown')
        fixed_version = (security_vuln.get('first_patched_version') or {}).get('identifier', 'Unknown')
        
        package_info = f"""
            Name: {name} ({ecosystem})
            Current Version: {current_version}
            Fixed Version: {fixed_version}"""
        
        return package_info.strip()

    def get_full_description(self):
        security_advisory = self.json.get("security_advisory", {})
        description = security_advisory.get("description", "").strip()
        
        if not description:
            return "No description available."
    
        # If description doesn't have sections (###), format as simple description
        if '###' not in description:
            formatted_desc = []
                
            # Add description under Impact section if it's a simple text
            formatted_desc.append(f"*Impact*\n{description}")
            
            # Add CVE/GHSA reference if available
            references = []
            if security_advisory.get("cve_id"):
                references.append(f"https://nvd.nist.gov/vuln/detail/{security_advisory['cve_id']}")
            if security_advisory.get("ghsa_id"):
                references.append(f"https://github.com/advisories/{security_advisory['ghsa_id']}")
            
            if references:
                formatted_desc.append("*References*\n" + "\n".join(references))
                
            return "\n\n".join(formatted_desc)
        
        # Existing section-based formatting logic
        sections = {}
        current_section = None
        current_content = []
        
        for line in description.split('\n'):
            line = line.strip()
            # Skip empty lines
            if not line:
                continue
            
            # Clean up numbered list formatting
            if line.startswith(('1.', 'a.')):
                continue
                
            if line.startswith('###'):
                if current_section and current_content:
                    sections[current_section] = '\n'.join(current_content).strip()
                current_section = line.replace('###', '').strip()
                current_content = []
            else:
                # Skip if line only contains numbers or letters with dots
                if not line.replace('.', '').strip().isalnum():
                    current_content.append(line)
        
        if current_section and current_content:
            sections[current_section] = '\n'.join(current_content).strip()
        
        formatted_desc = []
        for section in ['*Impact*', '*Patches*', '*Workarounds*', '*Recommendation*', '*References*']:
            if section.lower() in [s.lower() for s in sections.keys()]:
                section_content = sections.get(section) or sections.get(section.lower())
                formatted_desc.append(f"*{section}*\n{section_content}")
        
        return '\n\n'.join(formatted_desc)
    
    def get_cwe(self):
        cwes = self.json.get("security_advisory", {}).get("cwes", [])
        if not cwes:
            return None
            
        cwe_list = []
        for cwe in cwes:
            cwe_id = cwe.get("cwe_id", "")
            if cwe_id:
                cwe_list.append(cwe_id)
                
        return cwe_list
  
    def get_tool_name(self):
        return "dependabot"
    
    def get_cve(self):
        return self.json.get("security_advisory", {}).get("cve_id", "")