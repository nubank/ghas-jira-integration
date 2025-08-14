import jiralib
import logging
import itertools
import os

logger = logging.getLogger(__name__)

DIRECTION_G2J = 1
DIRECTION_J2G = 2
DIRECTION_BOTH = 3

ENABLE_ASSIGNEE_UPDATES = os.getenv('ENABLE_ASSIGNEE_UPDATES', 'false').lower() in ('true', '1', 'yes')

UPDATE_OPEN_ISSUES_ONLY = os.getenv('UPDATE_OPEN_ISSUES_ONLY', 'false').lower() in ('true', '1', 'yes')

ASSIGN_TO_SECRET_AUTHOR = os.getenv('ASSIGN_TO_SECRET_AUTHOR', 'true').lower() in ('true', '1', 'yes')


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
        
    def alert_reappeared(self, repo_id, alert_num, branch_ref="unknown"):
        a = self.github.getRepository(repo_id).get_alert(alert_num)
        self.sync(a, self.jira.fetch_issues(a.get_key()), DIRECTION_G2J, recent_event="reappeared_in_branch", branch_ref=branch_ref)

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

    def log_assignment_workflow_summary(self, alert, repo_id):
        if not alert:
            return
        alert_num = alert.number()
        logger.info(f"========================================================================")
        logger.info(f"Creating issue for alert {alert_num} - Started")

    def _extract_branch_name(self, branch_ref):
        if not branch_ref:
            return "unknown"
        if branch_ref.startswith("refs/heads/"):
            return branch_ref.replace("refs/heads/", "")
        return branch_ref

    def sync(self, alert, issues, in_direction, recent_event=None, branch_ref=None):
        if alert is None:
            # there is no alert, so we have to remove all issues
            # that have ever been associated with it
            for i in issues:
                i.delete()
            return None

        create_new_ticket = False
        
        if alert.get_state() is True and len(issues) > 0:
            if recent_event == "reappeared_in_branch":
                branch_name = self._extract_branch_name(branch_ref) if branch_ref else "unknown"
                
                # Collect issue states for monitoring
                done_issues = []
                open_issues = []
                
                for i in issues:
                    current_status = i.rawissue.fields.status.name.strip().lower()
                    if current_status in ['done', 'concluído', self.jira.endstate.lower()]:
                        done_issues.append(i.key())
                        create_new_ticket = True
                    else:
                        open_issues.append(i.key())
                
                if create_new_ticket:
                    logger.warning(
                        "ALERT_REAPPEARANCE_DETECTED: Alert {alert_num} in {repo_id} reappeared in branch {branch}. "
                        "Creating NEW ticket while preserving {done_count} completed issue(s): [{done_issues}]. "
                        "Alert_Type={alert_type} Branch={branch} Repository={repo_id} Alert_Number={alert_num}".format(
                            alert_num=alert.number(),
                            repo_id=alert.github_repo.repo_id,
                            branch=branch_name.upper(),
                            done_count=len(done_issues),
                            done_issues=', '.join(done_issues),
                            alert_type=alert.get_type()
                        )
                    )
                else:
                    logger.info(
                        "ALERT_REAPPEARANCE_OPEN_TICKETS: Alert {alert_num} in {repo_id} reappeared in branch {branch} "
                        "but has {open_count} open ticket(s): [{open_issues}]. Using existing ticket. "
                        "Alert_Type={alert_type} Branch={branch} Repository={repo_id} Alert_Number={alert_num}".format(
                            alert_num=alert.number(),
                            repo_id=alert.github_repo.repo_id,
                            branch=branch_name.upper(),
                            open_count=len(open_issues),
                            open_issues=', '.join(open_issues),
                            alert_type=alert.get_type()
                        )
                    )

        if len(issues) == 0 or create_new_ticket:
            self.log_assignment_workflow_summary(alert, alert.github_repo.repo_id)
            
            reappear_context = None
            if create_new_ticket and recent_event == "reappeared_in_branch":
                branch_name = self._extract_branch_name(branch_ref) if branch_ref else "unknown"
                reappear_context = f"Reappeared in branch {branch_name.upper()}"
            
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
                reappear_context=reappear_context,
            )
            
            if newissue is None:
                return None    
                 
            newissue.adjust_state(alert.get_state())
            
            if create_new_ticket:
                return alert.get_state()
                
            return alert.get_state()

        # make sure that each alert has at max
        # one issue associated with it
        if len(issues) > 1:
            issue_details = []
            open_count = 0
            closed_count = 0
            
            for i in issues:
                status = i.rawissue.fields.status.name
                is_open = i.get_state()
                issue_details.append(f"{i.key()}({status})")
                if is_open:
                    open_count += 1
                else:
                    closed_count += 1
            
            logger.warning(
                "MULTIPLE_ISSUES_DETECTED: Found {total_count} issues for alert {alert_num} in {repo_id}. "
                "Open: {open_count}, Closed: {closed_count}. Issues: [{issue_list}]. "
                "Starting cleanup process. Alert_Type={alert_type} Repository={repo_id} Alert_Number={alert_num}".format(
                    total_count=len(issues),
                    alert_num=alert.number(),
                    repo_id=alert.github_repo.repo_id,
                    open_count=open_count,
                    closed_count=closed_count,
                    issue_list=', '.join(issue_details),
                    alert_type=alert.get_type()
                )
            )
            
            # Sort issues, keeping the newest active ones first (sorted by ID in descending order)
            issues.sort(key=lambda i: -int(i.id()))
            
            # Filter for open issues first
            open_issues = [i for i in issues if i.get_state()]
            
            # If there are open issues, keep the newest one
            if open_issues:
                keep_issue = open_issues[0]
                selection_reason = "newest_open"
            else:
                # Otherwise keep the newest issue (even if closed)
                keep_issue = issues[0]
                selection_reason = "newest_overall"
                
            # Collect issues to be deleted for logging
            issues_to_delete = []
            for i in issues:
                if i.id() != keep_issue.id():
                    issues_to_delete.append(f"{i.key()}({i.rawissue.fields.status.name})")
                    i.delete()
            
            logger.warning(
                "MULTIPLE_ISSUES_CLEANUP: Kept issue {kept_issue}({kept_status}) using '{selection_reason}' strategy. "
                "Deleted {deleted_count} duplicate issue(s): [{deleted_issues}]. "
                "Alert_Type={alert_type} Repository={repo_id} Alert_Number={alert_num}".format(
                    kept_issue=keep_issue.key(),
                    kept_status=keep_issue.rawissue.fields.status.name,
                    selection_reason=selection_reason,
                    deleted_count=len(issues_to_delete),
                    deleted_issues=', '.join(issues_to_delete),
                    alert_type=alert.get_type(),
                    repo_id=alert.github_repo.repo_id,
                    alert_num=alert.number()
                )
            )
                    
            issues = [keep_issue]

        issue = issues[0]

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
            past_state_info = states.get(akey, None)
            
            if isinstance(past_state_info, bool):
                past_state = past_state_info
            elif isinstance(past_state_info, dict):
                past_state = past_state_info.get('state')
            else:
                past_state = None
                
            if alert is None or alert.get_state() != past_state:
                d = DIRECTION_G2J
            else:
                d = DIRECTION_J2G

            new_state = self.sync(alert, issues, d)

            if new_state is None:
                states.pop(akey, None)
            else:
                # Store enhanced state information
                import datetime
                states[akey] = {
                    'state': new_state,
                    'last_sync': datetime.datetime.now().isoformat(),
                    'tickets_created': len([i for i in issues if i.get_state()]) if issues else 0
                }

    def update_existing_assignees(self, repo_id):
        #Update assignees for all existing issues in a repository to prioritize maintainers
        if not ENABLE_ASSIGNEE_UPDATES:
            logger.info("Assignee updates are disabled (ENABLE_ASSIGNEE_UPDATES = False)")
            return 0, 0
        
        filter_mode = "open issues only" if UPDATE_OPEN_ISSUES_ONLY else "all issues"
        logger.info(
            "Updating assignees for existing issues in repository {repo_id} ({filter_mode})...".format(
                repo_id=repo_id, filter_mode=filter_mode
            )
        )

        repo = self.github.getRepository(repo_id)
        updated_count = 0
        failed_count = 0
        skipped_count = 0

        # Get all existing issues for this repository
        all_issues = self.jira.fetch_issues(repo.get_key())
        
        for issue in all_issues:
            # If UPDATE_OPEN_ISSUES_ONLY is enabled, skip closed/done issues
            if UPDATE_OPEN_ISSUES_ONLY:
                current_status = issue.rawissue.fields.status.name.strip().lower()
                if current_status in ['done', 'concluído', self.jira.endstate.lower()]:
                    logger.debug(f"Skipping closed issue {issue.key()} (status: {current_status})")
                    skipped_count += 1
                    continue
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

        if UPDATE_OPEN_ISSUES_ONLY and skipped_count > 0:
            logger.info(
                "Finished updating assignees for repository {repo_id}. Updated: {updated}, Failed: {failed}, Skipped (closed): {skipped}".format(
                    repo_id=repo_id, updated=updated_count, failed=failed_count, skipped=skipped_count
                )
            )
        else:
            logger.info(
                "Finished updating assignees for repository {repo_id}. Updated: {updated}, Failed: {failed}".format(
                    repo_id=repo_id, updated=updated_count, failed=failed_count
                )
            )
        
        return updated_count, failed_count
