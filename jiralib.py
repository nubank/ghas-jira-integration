from jira import JIRA
import re
import util
import logging
import requests
import json
import time

# JIRA Webhook events
UPDATE_EVENT = "jira:issue_updated"
CREATE_EVENT = "jira:issue_created"
DELETE_EVENT = "jira:issue_deleted"

tool_mapping = {
    "osv-scanner": "GitHub - Code Scanning - OSV-Scanner",
    "CodeQL": "GitHub - Code Scanning - CodeQL",
    "dependency-check": "GitHub - Code Scanning - Dependency-Check"
}

severity_mapping = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "warning": "Informative"
}

owasp_mapping = {
    "Alert": "2021:A04 - Insecure Design",
    "Secret": "2021:A02 - Cryptographic Failures"
}

DESC_TEMPLATE = """
{full_description}

*Location*
{location}

*Responsible Teams*
{responsible_teams}
This information was automatically collected from the repository's codeowners file, indicating the possible team responsible.

*Team Members*
{assignee}

*More details*
{alert_url}{reappear_context}

----
This issue was automatically generated from a GitHub alert, and will be automatically resolved once the underlying problem is fixed.
DO NOT MODIFY DESCRIPTION BELOW LINE.
REPOSITORY_NAME={repo_id}
ALERT_TYPE={alert_type}
ALERT_NUMBER={alert_num}
REPOSITORY_KEY={repo_key}
ALERT_KEY={alert_key}
"""

SECRET_DESC_TEMPLATE = """
Secret of type {short_desc} found in the repository.

*Responsible Teams*
{responsible_teams}
This information was automatically collected from the repository's codeowners file, indicating the possible team responsible.

*Team Members*
{assignee}

*More details*
{alert_url}{reappear_context}

----
This issue was automatically generated from a GitHub Secret Scanning alert.
DO NOT MODIFY DESCRIPTION BELOW LINE.
REPOSITORY_NAME={repo_id}
ALERT_TYPE={alert_type}
ALERT_NUMBER={alert_num}
REPOSITORY_KEY={repo_key}
ALERT_KEY={alert_key}
"""

STATE_ISSUE_SUMMARY = "[Code Scanning Issue States]"
STATE_ISSUE_KEY = util.make_key("gh2jira-state-issue")
STATE_ISSUE_TEMPLATE = """
This issue was automatically generated and contains states required for the synchronization between GitHub and JIRA.
DO NOT MODIFY DESCRIPTION BELOW LINE.
ISSUE_KEY={issue_key}
""".format(
    issue_key=STATE_ISSUE_KEY
)

logger = logging.getLogger(__name__)


class Jira:
    def __init__(self, url, user, token):
        self.url = url
        self.user = user
        self.token = token
        self.j = JIRA(url, basic_auth=(user, token))

    def auth(self):
        return self.user, self.token

    def getProject(self, projectkey, endstate, reopenstate, labels, auto_transition=True):
        return JiraProject(self, projectkey, endstate, reopenstate, labels, auto_transition)

    def list_hooks(self):
        resp = requests.get(
            "{api_url}/rest/webhooks/1.0/webhook".format(api_url=self.url),
            headers={"Content-Type": "application/json"},
            auth=self.auth(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

        for h in resp.json():
            yield h

    def create_hook(
        self,
        name,
        url,
        secret,
        events=[CREATE_EVENT, DELETE_EVENT, UPDATE_EVENT],
        filters={"issue-related-events-section": ""},
        exclude_body=False,
    ):
        data = json.dumps(
            {
                "name": name,
                "url": url + "?secret_token=" + secret,
                "events": events,
                "filters": filters,
                "excludeBody": exclude_body,
            }
        )
        resp = requests.post(
            "{api_url}/rest/webhooks/1.0/webhook".format(api_url=self.url),
            headers={"Content-Type": "application/json"},
            data=data,
            auth=self.auth(),
            timeout=util.REQUEST_TIMEOUT,
        )
        resp.raise_for_status()

        return resp.json()


class JiraProject:
    def __init__(self, jira, projectkey, endstate, reopenstate, labels, auto_transition=True):
        self.jira = jira
        self.labels = labels.split(",") if labels else []
        self.projectkey = projectkey
        self.j = self.jira.j
        self.endstate = endstate
        self.reopenstate = reopenstate
        self.auto_transition = auto_transition  # Enable/disable automatic status transitions

    def get_state_issue(self, issue_key="-"):
        if issue_key != "-":
            return self.j.issue(issue_key)

        issue_search = 'project={jira_project} and description ~ "{key}"'.format(
            jira_project='"{}"'.format(self.projectkey), key=STATE_ISSUE_KEY
        )
        issues = list(
            filter(
                lambda i: i.fields.summary == STATE_ISSUE_SUMMARY,
                self.j.search_issues(issue_search, maxResults=0),
            )
        )

        if len(issues) == 0:
            return self.j.create_issue(
                project=self.projectkey,
                summary=STATE_ISSUE_SUMMARY,
                description=STATE_ISSUE_TEMPLATE,
                issuetype={"name": "Vulnerability - General"},
                labels=self.labels,
            )
        elif len(issues) > 1:
            issues.sort(key=lambda i: i.id())  # keep the oldest issue
            for i in issues[1:]:
                i.delete()

        i = issues[0]

        # When fetching issues via the search_issues() function, we somehow
        # cannot access the attachments. To do that, we need to fetch the issue
        # via the issue() function first.
        return self.j.issue(i.key)

    def fetch_repo_state(self, repo_id, issue_key="-"):
        i = self.get_state_issue(issue_key)

        for a in i.fields.attachment:
            if a.filename == repo_id_to_fname(repo_id):
                return util.state_from_json(a.get())

        return {}

    def save_repo_state(self, repo_id, state, issue_key="-"):
        i = self.get_state_issue(issue_key)

        # remove previous state files for the given repo_id
        for a in i.fields.attachment:
            if a.filename == repo_id_to_fname(repo_id):
                self.j.delete_attachment(a.id)

        # attach the new state file
        self.jira.attach_file(
            i.key, repo_id_to_fname(repo_id), util.state_to_json(state)
        )

    def create_issue(
        self,
        repo_id,
        short_desc,
        long_desc,
        alert_url,
        alert_type,
        alert_num,
        repo_key,
        alert_key,
        tool_name,
        severity,
        full_description,
        identification_date,
        language,
        cwe_list,
        location,
        responsible_teams,
        all_members,
        cve,
        alert,
        reappear_context=None
    ):

        template = SECRET_DESC_TEMPLATE if alert_type == "Secret" else DESC_TEMPLATE
        assignee_value = alert.get_valid_assignees() if alert else None
        unique_assignees = list(dict.fromkeys(assignee_value)) if assignee_value else None
        formatted_assignees = ", ".join(unique_assignees) if unique_assignees else "No assignee found"

        summary = (
            f"{short_desc} secret found in mini-meta-repo" 
            if alert_type == "Secret" 
            else long_desc
        )
        
        # Add reappearance context to summary if provided
        if reappear_context:
            summary = f"{summary} - {reappear_context}"
        
        cve_field = [cve] if cve is not None else []
        language = language if language else None

        raw = self.j.create_issue(
            project=self.projectkey,
            summary=summary,
            description=template.format(
                long_desc=long_desc,
                short_desc=short_desc,
                full_description=full_description,
                alert_url=alert_url,
                repo_id=repo_id,
                alert_type=alert_type,
                alert_num=alert_num,
                repo_key=repo_key,
                alert_key=alert_key,
                location=location,
                responsible_teams=responsible_teams,
                all_members=all_members,
                assignee=formatted_assignees,
                reappear_context=f"\n\n*{reappear_context}*" if reappear_context else "",
            ),
            issuetype={"name": "Vulnerability - General"},
            labels=self.labels,
            customfield_12957='Unknown',
            customfield_12927={'value': 'Unknown'},
            customfield_13397={'value': (tool_mapping.get(tool_name, 'GitHub - Secret Scanning'))},
            customfield_10457={'value': (severity_mapping.get(severity, 'High'))},
            customfield_12954={'value': 'Internal'},
            customfield_16751=['mini-meta-repo'],
            customfield_16748=alert_url,
            customfield_21734=short_desc if alert_type == 'Alert' else None,
            customfield_10611=identification_date,
            customfield_15569={'value': 'Nubank'},
            customfield_16749=language if alert_type == 'Secret' else None,
            customfield_17255=cwe_list,
            customfield_10548={'value': (owasp_mapping.get(alert_type, None))},
            customfield_18385=['MobSec'],
            customfield_21106={'value': short_desc} if alert_type == 'Secret' else None,
            customfield_17301=cve_field
        )

        valid_assignees = alert.get_valid_assignees()
        
        prioritized_assignees = alert.get_prioritized_assignees()
        maintainers = prioritized_assignees.get('maintainers', [])
        members = prioritized_assignees.get('members', [])
        
        assigned = False
        assigned_user = None
        
        # Try maintainers first
        for assignee_name in maintainers:
            try:
                assignable_users = self.j._get_json(
                    'user/assignable/search',
                    params={
                        'project': self.projectkey,
                        'query': assignee_name,
                        'maxResults': 1
                    }
                )
                
                if assignable_users and len(assignable_users) > 0:
                    account_id = assignable_users[0]['accountId']
                    self.j._session.put(
                        f"{self.j._options['server']}/rest/api/2/issue/{raw.key}/assignee",
                        json={'accountId': account_id}
                    )
                    assigned = True
                    assigned_user = assignee_name
                    break
            except Exception:
                continue

        # If no maintainer could be assigned, try regular members
        if not assigned:
            for assignee_name in members:
                try:
                    assignable_users = self.j._get_json(
                        'user/assignable/search',
                        params={
                            'project': self.projectkey,
                            'query': assignee_name,
                            'maxResults': 1
                        }
                    )
                    
                    if assignable_users and len(assignable_users) > 0:
                        account_id = assignable_users[0]['accountId']
                        self.j._session.put(
                            f"{self.j._options['server']}/rest/api/2/issue/{raw.key}/assignee",
                            json={'accountId': account_id}
                        )
                        assigned = True
                        assigned_user = assignee_name
                        break
                except Exception:
                    continue
        
        # Refresh the issue to ensure we have the latest assignee information
        # Add a small delay to allow Jira to process the assignment
        time.sleep(0.5)  # Wait 500ms for Jira to process the assignment
        
        raw = self.j.issue(raw.key)
        jira_issue = JiraIssue(self, raw)
        
        # Update status based on assignee state
        jira_issue.update_status_based_on_assignee()
        
        # Simple issue creation confirmation
        logger.info(f"Issue {raw.key} created for alert {alert_num} - Finished")

        return jira_issue

    def fetch_issues(self, key):
        issue_search = 'project={jira_project} and description ~ "{key}"'.format(
            jira_project='"{}"'.format(self.projectkey), key=key
        )
        issues = list(
            filter(
                lambda i: i.is_managed(),
                [
                    JiraIssue(self, raw)
                    for raw in self.j.search_issues(issue_search, maxResults=0)
                ],
            )
        )
        logger.debug(
            "Search {search} returned {num_results} results.".format(
                search=issue_search, num_results=len(issues)
            )
        )
        return issues


class JiraIssue:
    def __init__(self, project, rawissue):
        self.project = project
        self.rawissue = rawissue
        self.j = self.project.j
        self.endstate = self.project.endstate
        self.reopenstate = self.project.reopenstate
        self.labels = self.project.labels

    def is_managed(self):
        if parse_alert_info(self.rawissue.fields.description)[0] is None:
            return False
        return True

    def get_alert_info(self):
        return parse_alert_info(self.rawissue.fields.description)

    def key(self):
        return self.rawissue.key

    def id(self):
        return self.rawissue.id

    def delete(self):
        logger.info("Deleting issue {ikey}.".format(ikey=self.key()))
        self.rawissue.delete()

    def update_assignee_with_priority(self, alert):
        """Update the assignee of an existing issue, prioritizing maintainers"""
        if not alert:
            logger.warning(f"No alert provided for updating assignee of issue {self.key()}")
            return False
            
        # Get prioritized assignees (maintainers first, then members)
        prioritized_assignees = alert.get_prioritized_assignees()
        maintainers = prioritized_assignees.get('maintainers', [])
        members = prioritized_assignees.get('members', [])
        
        # Get current assignee
        current_assignee = None
        if hasattr(self.rawissue.fields, 'assignee') and self.rawissue.fields.assignee:
            current_assignee = self.rawissue.fields.assignee.displayName
                    
        # Try maintainers first
        assigned = False
        for assignee_name in maintainers:
            if current_assignee == assignee_name:
                logger.info(f"Issue {self.key()} already assigned to maintainer {assignee_name}")
                return True
                
            try:
                assignable_users = self.j._get_json(
                    'user/assignable/search',
                    params={
                        'project': self.project.projectkey,
                        'query': assignee_name,
                        'maxResults': 1
                    }
                )
                
                if assignable_users and len(assignable_users) > 0:
                    account_id = assignable_users[0]['accountId']
                    self.j._session.put(
                        f"{self.j._options['server']}/rest/api/2/issue/{self.key()}/assignee",
                        json={'accountId': account_id}
                    )
                    logger.info(f"Updated issue {self.key()} assignee to maintainer {assignee_name}")
                    assigned = True
                    break
                else:
                    logger.debug(f"Maintainer {assignee_name} not found in assignable users for project {self.project.projectkey}")
                    continue
            except Exception as e:
                logger.debug(f"Failed to assign maintainer {assignee_name} to issue {self.key()}: {e}")
                continue

        # If no maintainer could be assigned, try regular members
        if not assigned:
            for assignee_name in members:
                if current_assignee == assignee_name:
                    logger.info(f"Issue {self.key()} already assigned to member {assignee_name}")
                    return True
                    
                try:
                    assignable_users = self.j._get_json(
                        'user/assignable/search',
                        params={
                            'project': self.project.projectkey,
                            'query': assignee_name,
                            'maxResults': 1
                        }
                    )
                    
                    if assignable_users and len(assignable_users) > 0:
                        account_id = assignable_users[0]['accountId']
                        self.j._session.put(
                            f"{self.j._options['server']}/rest/api/2/issue/{self.key()}/assignee",
                            json={'accountId': account_id}
                        )
                        logger.info(f"Updated issue {self.key()} assignee to member {assignee_name}")
                        assigned = True
                        break
                    else:
                        logger.debug(f"Member {assignee_name} not found in assignable users for project {self.project.projectkey}")
                        continue
                except Exception as e:
                    logger.debug(f"Failed to assign member {assignee_name} to issue {self.key()}: {e}")
                    continue
        
        # Update status based on assignment result
        if assigned:
            self.update_status_based_on_assignee()
        
        if not assigned:
            logger.warning(f"Could not update assignee for issue {self.key()}")
            
        return assigned

    def update_assignee_if_needed(self, alert):
        """Update assignee only if current assignee is not a maintainer"""
        if not alert:
            return False
            
        # Get current assignee
        current_assignee = None
        if hasattr(self.rawissue.fields, 'assignee') and self.rawissue.fields.assignee:
            current_assignee = self.rawissue.fields.assignee.displayName
            
        # If no current assignee, definitely update
        if not current_assignee:
            logger.info(f"Issue {self.key()} has no assignee, updating...")
            return self.update_assignee_with_priority(alert)
            
        # Check if current assignee is a maintainer
        prioritized_assignees = alert.get_prioritized_assignees()
        maintainers = prioritized_assignees.get('maintainers', [])
        
        if current_assignee in maintainers:
            logger.info(f"Issue {self.key()} already assigned , no update needed.")
            return True
        else:
            logger.info(f"Issue {self.key()} assigned to non-maintainer {current_assignee}, updating to prioritize maintainers...")
            return self.update_assignee_with_priority(alert)

    def remove_assignee(self):
        """Remove the assignee from the issue and update status to 'To Do'"""
        try:
            # Remove assignee
            self.j._session.put(
                f"{self.j._options['server']}/rest/api/2/issue/{self.key()}/assignee",
                json={'accountId': None}
            )
            logger.info(f"Removed assignee from issue {self.key()}")
            
            # Update status to reflect unassignment
            self.update_status_based_on_assignee()
            
            return True
        except Exception as e:
            logger.error(f"Failed to remove assignee from issue {self.key()}: {e}")
            return False

    def update_status_based_on_assignee(self):
        """Update issue status based on whether it has an assignee"""
        # Check if auto-transition is enabled
        if not self.project.auto_transition:
            logger.debug(f"Auto-transition disabled for project {self.project.projectkey}, skipping status update for issue {self.key()}")
            return
            
        try:
            # Refresh the issue to get the most current state including assignee
            self.rawissue = self.j.issue(self.rawissue.key)
            
            # Check if issue has an assignee
            has_assignee = (hasattr(self.rawissue.fields, 'assignee') and 
                          self.rawissue.fields.assignee is not None)
            
            current_status = self.rawissue.fields.status.name.strip().lower()
            assignee_name = self.rawissue.fields.assignee.displayName if has_assignee else "None"
            
            logger.debug(f"Issue {self.key()}: current_status='{current_status}', has_assignee={has_assignee}, assignee='{assignee_name}'")
            
            # Status mapping for normalization
            status_mapping = {
                'concluído': 'done',
                'a fazer': 'to do',
                'em andamento': 'in progress',
                'waiting fix': 'waiting fix',
                'aguardando correção': 'waiting fix',
                'to do': 'to do',
                'done': 'done',
                'in progress': 'in progress'
            }
            
            normalized_status = status_mapping.get(current_status, current_status)
            logger.debug(f"Issue {self.key()}: normalized_status='{normalized_status}'")
            
            if has_assignee:
                if normalized_status == 'to do':
                    logger.info(f"Issue has assignee and is in 'To Do', transitioning to 'Waiting Fix'.")
                    if self.transition_to_waiting_fix():
                        logger.debug(f"Issue {self.key()} successfully moved to 'Waiting Fix' status after assignment")
                    else:
                        logger.warning(f"Failed to transition issue {self.key()} to 'Waiting Fix'")
                else:
                    logger.info(f"Issue {self.key()} has assignee but is not in 'To Do' status (current: '{normalized_status}'), no transition needed")
            else:
                if normalized_status == 'waiting fix':
                    logger.info(f"Issue {self.key()} has no assignee and is in 'Waiting Fix', transitioning to 'To Do'")
                    if self.transition_to_todo():
                        logger.info(f"Issue {self.key()} successfully moved back to 'To Do' status after unassignment")
                    else:
                        logger.warning(f"Failed to transition issue {self.key()} to 'To Do'")
                else:
                    logger.debug(f"Issue {self.key()} has no assignee but is not in 'Waiting Fix' status (current: '{normalized_status}'), no transition needed")
                    
        except Exception as e:
            logger.warning(f"Failed to update status for issue {self.key()} based on assignee: {e}")

    def transition_to_waiting_fix(self):
        """Transition issue to 'Waiting Fix' status"""
        possible_transitions = [
            'Waiting Fix', 'waiting fix', 'Waiting fix'
        ]
        
        try:
            self.rawissue = self.j.issue(self.rawissue.key)
            transitions = self.j.transitions(self.rawissue)
            available_transitions = {t["name"]: t["id"] for t in transitions}
                        
            # Try to find a matching transition
            for transition_name in possible_transitions:
                if transition_name in available_transitions:
                    self.j.transition_issue(self.rawissue, available_transitions[transition_name])
                    logger.info(f"Successfully transitioned issue to '{transition_name}.'")
                    return True
                    
            logger.warning(f"No 'Waiting Fix' transition available for issue {self.key()}. Available transitions: {list(available_transitions.keys())}")
            return False
            
        except Exception as e:
            logger.error(f"Error transitioning issue {self.key()} to 'Waiting Fix': {e}")
            return False

    def transition_to_todo(self):
        """Transition issue to 'To Do' status"""
        possible_transitions = [
            'To Do', 'to do', 'TO DO',
            'A Fazer', 'a fazer', 'A FAZER', 
            'Todo', 'todo', 'TODO',
            'Open', 'open', 'OPEN'
        ]
        
        try:
            # Refresh the issue to get current state
            self.rawissue = self.j.issue(self.rawissue.key)
            transitions = self.j.transitions(self.rawissue)
            available_transitions = {t["name"]: t["id"] for t in transitions}
                        
            # Try to find a matching transition
            for transition_name in possible_transitions:
                if transition_name in available_transitions:
                    self.j.transition_issue(self.rawissue, available_transitions[transition_name])
                    logger.info(f"Successfully transitioned issue to '{transition_name}.'")
                    return True
                    
            logger.warning(f"No 'To Do' transition available for issue {self.key()}. Available transitions: {list(available_transitions.keys())}")
            return False
            
        except Exception as e:
            logger.error(f"Error transitioning issue {self.key()} to 'To Do': {e}")
            return False

    def transition_to_replanning(self, branch_name):
        """Transition Done issue to Replanning status when alert reappears"""
        try:
            logger.info(f"Transitioning issue {self.key()} from Done to Replanning due to reappearance in branch {branch_name}")
            
            # Add comment about reappearance
            reappear_comment = f"Alert reappeared in branch {branch_name}. Moving to Replanning for investigation."
            self.j.add_comment(self.rawissue, reappear_comment)
            
            # Refresh the issue to get current state
            self.rawissue = self.j.issue(self.rawissue.key)
            transitions = self.j.transitions(self.rawissue)
            available_transitions = {t["name"]: t["id"] for t in transitions}
                        
            # Try different possible names for the Replanning transition
            replanning_transitions = [
                "Replanning", "replanning", "REPLANNING",
                "Replan", "replan", "REPLAN", 
                "Re-planning", "re-planning", "RE-PLANNING",
                "Reopen", "reopen", "REOPEN"
            ]
            
            for transition_name in replanning_transitions:
                if transition_name in available_transitions:
                    logger.info(f"Found transition '{transition_name}' for issue {self.key()}")
                    self.j.transition_issue(self.rawissue, available_transitions[transition_name])
                    logger.info(f"Successfully transitioned issue to {transition_name}.")
                    return True
            
            # If no specific Replanning transition found, try to reopen to To Do
            logger.warning(f"No Replanning transition found for issue {self.key()}, attempting to reopen")
            if self.transition_to_todo():
                logger.info(f"Successfully reopened issue {self.key()} to active status")
                return True
            else:
                logger.error(f"Failed to reopen issue {self.key()}")
                return False
                
        except Exception as e:
            logger.error(f"Error transitioning issue {self.key()} to Replanning: {e}")
            return False

    def debug_issue_state(self):
        """Debug method to log detailed issue state information"""
        try:
            # Refresh the issue to get current state
            self.rawissue = self.j.issue(self.rawissue.key)
            
            # Log current status
            current_status = self.rawissue.fields.status.name
            logger.info(f"Issue {self.key()} current status: '{current_status}'")
            
            # Log assignee
            has_assignee = (hasattr(self.rawissue.fields, 'assignee') and 
                          self.rawissue.fields.assignee is not None)
            assignee_name = self.rawissue.fields.assignee.displayName if has_assignee else "None"
            logger.info(f"Issue {self.key()} assignee: '{assignee_name}'")
            
            # Log available transitions
            transitions = self.j.transitions(self.rawissue)
            available_transitions = [t["name"] for t in transitions]
            logger.info(f"Issue {self.key()} available transitions: {available_transitions}")
            
        except Exception as e:
            logger.error(f"Error getting debug info for issue {self.key()}: {e}")

    def get_state(self):
        return self.parse_state(self.rawissue.fields.status.name)

    def adjust_state(self, state):
        if state: 
            current_status = self.rawissue.fields.status.name.strip().lower()
            if current_status == 'done':
                self.transition("Reopen")
            else:
                self.transition(self.reopenstate)
        else:
            self.transition(self.endstate)

    def parse_state(self, raw_state):
        return raw_state != self.endstate

    def transition(self, transition):
        current_status = self.rawissue.fields.status.name.strip().lower()
        target_status = transition.strip().lower()
        
        status_mapping = {
            'concluído': 'Done',
            'a fazer': 'to do',
            'em andamento': 'in progress',
        }
        
        normalized_status = status_mapping.get(current_status, current_status)

        if normalized_status == target_status:
            return
    
        transitions = self.j.transitions(self.rawissue)
        available_transitions = {t["name"]: t["id"] for t in transitions}

        if transition not in available_transitions:
            return
    
        try:
            self.j.transition_issue(self.rawissue, available_transitions[transition])
            action = "Reopening" if transition == self.reopenstate else "Changing status to"
            logger.info("{action} issue {issue_key}.".format(action=action, issue_key=self.rawissue.key))
        except Exception as e:
            logger.error("Error transitioning issue {0}: {1}".format(self.rawissue.key, e))
    
    def persist_labels(self, labels):
        if labels:
            self.rawissue.update(fields={"labels": self.labels})
        
def parse_alert_info(desc):
    """
    Parse all the fields in an issue's description and return
    them as a tuple. If parsing fails for one of the fields,
    return a tuple of None's.
    """
    failed = None, None, None, None
    m = re.search("REPOSITORY_NAME=(.*)$", desc, re.MULTILINE)
    if m is None:
        return failed
    repo_id = m.group(1)

    m = re.search("ALERT_TYPE=(.*)$", desc, re.MULTILINE)
    if m is None:
        alert_type = None
    else:
        alert_type = m.group(1)
    m = re.search("ALERT_NUMBER=(.*)$", desc, re.MULTILINE)

    if m is None:
        return failed
    alert_num = int(m.group(1))
    m = re.search("REPOSITORY_KEY=(.*)$", desc, re.MULTILINE)
    if m is None:
        return failed
    repo_key = m.group(1)
    m = re.search("ALERT_KEY=(.*)$", desc, re.MULTILINE)
    if m is None:
        return failed
    alert_key = m.group(1)

    return repo_id, alert_num, repo_key, alert_key, alert_type


def repo_id_to_fname(repo_id):
    return repo_id.replace("/", "^") + ".json"
