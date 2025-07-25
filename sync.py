import jiralib
import logging
import itertools
import os

logger = logging.getLogger(__name__)

DIRECTION_G2J = 1
DIRECTION_J2G = 2
DIRECTION_BOTH = 3

# Configuration flag to enable/disable assignee updates for existing issues
# Can be controlled via environment variable ENABLE_ASSIGNEE_UPDATES (default: false)
ENABLE_ASSIGNEE_UPDATES = os.getenv('ENABLE_ASSIGNEE_UPDATES', 'true').lower() in ('false', '1', 'yes')


class Sync:
    def __init__(self, github, jira_project, direction=DIRECTION_BOTH):
        self.github = github
        self.jira = jira_project
        self.direction = direction
        self.labels = self.jira.labels

    def alert_created(self, repo_id, alert_num):
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_G2J)

    def alert_changed(self, repo_id, alert_num):
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_G2J)

    def alert_fixed(self, repo_id, alert_num):
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_G2J)

    def issue_created(self, desc):
        repo_id, alert_num, _, _, _ = jiralib.parse_alert_info(desc)
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_J2G)

    def issue_changed(self, desc):
        repo_id, alert_num, _, _, _ = jiralib.parse_alert_info(desc)
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_J2G)

    def issue_deleted(self, desc):
        repo_id, alert_num, _, _, _ = jiralib.parse_alert_info(desc)
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_J2G)

    def sync(self, alert, issues, in_direction):
        if alert is None:
            # there is no alert, so we have to remove all issues
            # that have ever been associated with it
            for i in issues:
                i.delete()
            return None

        # Check if this is a reopened alert - if the alert is open but existing issues are closed
        create_new_ticket = False
        if alert.get_state() is True and len(issues) > 0:
            for i in issues:
                current_status = i.rawissue.fields.status.name.strip().lower()
                if current_status in ['done', 'concluído', self.jira.endstate.lower()]:
                    # This is a reopened alert - create a new ticket without deleting existing ones
                    logger.info(
                        "Alert {alert_num} in {repo_id} was reopened. Creating new ticket while preserving existing ones.".format(
                            alert_num=alert.number(),
                            repo_id=alert.github_repo.repo_id,
                        )
                    )
                    create_new_ticket = True
                    break

        # Create a new issue if there are no issues or if the alert was reopened
        if len(issues) == 0 or create_new_ticket:
            newissue = self.jira.create_issue(
                alert.github_repo.repo_id,
                alert.short_desc(),
                alert.long_desc(),
                alert.hyperlink(),
                alert.get_type(),
                alert.number(),
                alert.github_repo.get_key(),
                alert.get_key(),
                alert.get_tool_name(),
                alert.get_severity(),
                alert.get_full_description(),
                alert.get_identification_date(),
                alert.get_language(),
                alert.get_cwe(),
                alert.get_location(),
                alert.get_responsible_teams(),
                alert.get_team_members(),
                alert.get_cve(),
                alert=alert,
            )
            
            if newissue is None:
                return None    
                 
            newissue.adjust_state(alert.get_state())
            
            # If we created a new ticket for a reopened alert, we're done here
            if create_new_ticket:
                return alert.get_state()
                
            return alert.get_state()

        # make sure that each alert has at max
        # one issue associated with it
        if len(issues) > 1:
            # Sort issues, keeping the newest active ones first (sorted by ID in descending order)
            issues.sort(key=lambda i: -int(i.id()))
            
            # Filter for open issues first
            open_issues = [i for i in issues if i.get_state()]
            
            # If there are open issues, keep the newest one
            if open_issues:
                keep_issue = open_issues[0]
            else:
                # Otherwise keep the newest issue (even if closed)
                keep_issue = issues[0]
                
            # Delete all other issues except the one we're keeping
            for i in issues:
                if i.id() != keep_issue.id():
                    i.delete()
                    
            issues = [keep_issue]

        issue = issues[0]

        # Update assignee for existing issues to ensure maintainers are prioritized
        # This can be disabled by setting ENABLE_ASSIGNEE_UPDATES = False
        if alert and ENABLE_ASSIGNEE_UPDATES:
            issue.update_assignee_if_needed(alert)

        # make sure alert and issue are in the same state
        if self.direction & DIRECTION_G2J and self.direction & DIRECTION_J2G:
            d = in_direction
        else:
            d = self.direction

        if d & DIRECTION_G2J or not alert.can_transition():
            # The user treats GitHub as the source of truth.
            # Also, if the alert to be synchronized is already "fixed"
            # then even if the user treats JIRA as the source of truth,
            # we have to push back the state to JIRA, because "fixed"
            # alerts cannot be transitioned to "open"
            issue.adjust_state(alert.get_state())
            issue.persist_labels(self.labels)
            return alert.get_state()
        else:
            # The user treats JIRA as the source of truth
            alert.adjust_state(issue.get_state())
            issue.persist_labels(self.labels)
            return issue.get_state()

    def sync_repo(self, repo_id, states=None):
        logger.info(
            "Performing full sync on repository {repo_id}...".format(repo_id=repo_id)
        )

        repo = self.github.getRepository(repo_id)
        states = {} if states is None else states
        pairs = {}

        # gather alerts
        for a in itertools.chain(repo.get_secrets(), repo.get_alerts()):
            pairs[a.get_key()] = (a, [])

        # gather issues
        for i in self.jira.fetch_issues(repo.get_key()):
            _, _, _, alert_key, _ = i.get_alert_info()
            if alert_key not in pairs:
                pairs[alert_key] = (None, [])
            pairs[alert_key][1].append(i)

        # remove unused states
        for k in list(states.keys()):
            if k not in pairs:
                del states[k]

        # perform sync
        for akey, (alert, issues) in pairs.items():
            past_state = states.get(akey, None)
            if alert is None or alert.get_state() != past_state:
                d = DIRECTION_G2J
            else:
                d = DIRECTION_J2G

            new_state = self.sync(alert, issues, d)

            if new_state is None:
                states.pop(akey, None)
            else:
                states[akey] = new_state

    def update_existing_assignees(self, repo_id):
        """Update assignees for all existing issues in a repository to prioritize maintainers"""
        if not ENABLE_ASSIGNEE_UPDATES:
            logger.info("Assignee updates are disabled (ENABLE_ASSIGNEE_UPDATES = False)")
            return 0, 0
            
        logger.info(
            "Updating assignees for existing issues in repository {repo_id}...".format(repo_id=repo_id)
        )

        repo = self.github.getRepository(repo_id)
        updated_count = 0
        failed_count = 0

        # Get all existing issues for this repository
        for issue in self.jira.fetch_issues(repo.get_key()):
            try:
                # Parse the alert info from the issue
                repo_id_from_issue, alert_num, _, _, _ = issue.get_alert_info()
                
                if repo_id_from_issue and alert_num:
                    # Get the corresponding alert
                    alert = repo.get_alert(alert_num)
                    if alert:
                        # Update the assignee if needed
                        if issue.update_assignee_if_needed(alert):
                            updated_count += 1
                        else:
                            failed_count += 1
                    else:
                        logger.warning(f"Could not find alert {alert_num} for issue {issue.key()}")
                        failed_count += 1
                else:
                    logger.warning(f"Could not parse alert info from issue {issue.key()}")
                    failed_count += 1
                    
            except Exception as e:
                logger.error(f"Error updating assignee for issue {issue.key()}: {e}")
                failed_count += 1

        logger.info(
            "Finished updating assignees for repository {repo_id}. Updated: {updated}, Failed: {failed}".format(
                repo_id=repo_id, updated=updated_count, failed=failed_count
            )
        )
        
        return updated_count, failed_count
