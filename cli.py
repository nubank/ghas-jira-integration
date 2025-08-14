import argparse
import ghlib
import jiralib
import os
import sys
import json
import util
from sync import Sync, DIRECTION_G2J, DIRECTION_J2G, DIRECTION_BOTH
import logging
import server
import anticrlf

root = logging.getLogger()
root.setLevel(logging.DEBUG)

handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(anticrlf.LogFormatter("%(levelname)s:%(name)s:%(message)s"))
handler.setLevel(logging.DEBUG)
root.addHandler(handler)

# Suppress verbose HTTP debug logs from third-party libraries
logging.getLogger("urllib3.connectionpool").setLevel(logging.WARNING)
logging.getLogger("requests.packages.urllib3").setLevel(logging.WARNING)
logging.getLogger("github").setLevel(logging.INFO)
logging.getLogger("jira").setLevel(logging.INFO)


def fail(msg):
    print(msg)
    sys.exit(1)


def direction_str_to_num(dstr):
    if dstr == "gh2jira":
        return DIRECTION_G2J
    elif dstr == "jira2gh":
        return DIRECTION_J2G
    elif dstr == "both":
        return DIRECTION_BOTH
    else:
        fail('Unknown direction argument "{direction}"!'.format(direction=dstr))


def serve(args):
    if not args.gh_url or not args.jira_url:
        fail("Both GitHub and JIRA URL have to be specified!")

    if not args.gh_token:
        fail("No GitHub token specified!")

    if not args.jira_user or not args.jira_token:
        fail("No JIRA credentials specified!")

    if not args.jira_project:
        fail("No JIRA project specified!")

    if not args.secret:
        fail("No Webhook secret specified!")

    github = ghlib.GitHub(args.gh_url, args.gh_token)
    jira = jiralib.Jira(args.jira_url, args.jira_user, args.jira_token)
    
    # Determine auto-transition setting
    auto_transition = not args.no_auto_transition if hasattr(args, 'no_auto_transition') else True
    
    # Set secret author assignment if specified
    if hasattr(args, 'assign_secret_author') and args.assign_secret_author:
        import os
        os.environ['ASSIGN_TO_SECRET_AUTHOR'] = 'true'
    
    s = Sync(
        github,
        jira.getProject(
            args.jira_project,
            args.issue_end_state or "Done",
            args.issue_reopen_state or "To Do", 
            args.jira_labels or "",
            auto_transition,
        ),
        direction=direction_str_to_num(args.direction),
    )
    server.run_server(s, args.secret, port=args.port)


def sync(args):
    if not args.gh_url or not args.jira_url:
        fail("Both GitHub and JIRA URL have to be specified!")

    if not args.gh_token:
        fail("No GitHub credentials specified!")

    if not args.jira_user or not args.jira_token:
        fail("No JIRA credentials specified!")

    if not args.jira_project:
        fail("No JIRA project specified!")

    if not args.gh_org:
        fail("No GitHub organization specified!")

    if not args.gh_repo:
        fail("No GitHub repository specified!")

    github = ghlib.GitHub(args.gh_url, args.gh_token)
    jira = jiralib.Jira(args.jira_url, args.jira_user, args.jira_token)
    
    # Determine auto-transition setting
    auto_transition = not args.no_auto_transition if hasattr(args, 'no_auto_transition') else True
    
    # Set secret author assignment if specified
    if hasattr(args, 'assign_secret_author') and args.assign_secret_author:
        import os
        os.environ['ASSIGN_TO_SECRET_AUTHOR'] = 'true'
    
    jira_project = jira.getProject(
        args.jira_project,
        args.issue_end_state,
        args.issue_reopen_state,
        args.jira_labels,
        auto_transition,
    )
    repo_id = args.gh_org + "/" + args.gh_repo

    if args.state_file:
        if args.state_issue:
            fail("--state-file and --state-issue are mutually exclusive!")

        state = util.state_from_file(args.state_file)
    elif args.state_issue:
        state = jira_project.fetch_repo_state(repo_id, args.state_issue)
    else:
        state = {}

    s = Sync(github, jira_project, direction=direction_str_to_num(args.direction))
    s.sync_repo(repo_id, states=state)

    if args.state_file:
        util.state_to_file(args.state_file, state)
    elif args.state_issue:
        jira_project.save_repo_state(repo_id, state, args.state_issue)


def update_assignees(args):
    if not args.gh_url or not args.jira_url:
        fail("Both GitHub and JIRA URL have to be specified!")

    if not args.gh_token:
        fail("No GitHub token specified!")

    if not args.jira_user or not args.jira_token:
        fail("No JIRA credentials specified!")

    if not args.jira_project:
        fail("No JIRA project specified!")

    if not args.gh_org or not args.gh_repo:
        fail("Both GitHub organization and repository have to be specified!")

    repo_id = args.gh_org + "/" + args.gh_repo

    # create connections
    github = ghlib.GitHub(args.gh_url, args.gh_token)
    jira = jiralib.Jira(args.jira_url, args.jira_user, args.jira_token)
    
    # Determine auto-transition setting
    auto_transition = not args.no_auto_transition if hasattr(args, 'no_auto_transition') else True
    
    # Set secret author assignment if specified
    if hasattr(args, 'assign_secret_author') and args.assign_secret_author:
        import os
        os.environ['ASSIGN_TO_SECRET_AUTHOR'] = 'true'
    
    jira_project = jira.getProject(
        args.jira_project,
        args.issue_end_state or "Done",
        args.issue_reopen_state or "To Do",
        args.jira_labels or "",
        auto_transition,
    )

    # Update assignees for existing issues
    sync = Sync(github, jira_project, DIRECTION_G2J)  # Direction doesn't matter for this operation
    updated_count, failed_count = sync.update_existing_assignees(repo_id)
    
    print(f"Update completed for repository {repo_id}:")
    print(f"  Successfully updated: {updated_count} issues")
    print(f"  Failed to update: {failed_count} issues")


def check_hooks(args):
    pass


def install_hooks(args):
    if not args.hook_url:
        fail("No hook URL specified!")

    if not args.secret:
        fail("No hook secret specified!")

    if not args.gh_url and not args.jira_url:
        fail("Neither GitHub nor JIRA URL specified!")

    # user wants to install a github hook
    if args.gh_url:
        if not args.gh_token:
            fail("No GitHub token specified!")

        if not args.gh_org:
            fail("No GitHub organization specified!")

        github = ghlib.GitHub(args.gh_url, args.gh_token)

        if args.gh_repo:
            ghrepo = github.getRepository(args.gh_org + "/" + args.gh_repo)
            ghrepo.create_hook(url=args.hook_url, secret=args.secret)
        else:
            github.create_org_hook(url=args.hook_url, secret=args.secret)

    # user wants to install a JIRA hook
    if args.jira_url:
        if not args.jira_user or not args.jira_token:
            fail("No JIRA credentials specified!")
        jira = jiralib.Jira(args.jira_url, args.jira_user, args.jira_token)
        jira.create_hook("github_jira_synchronization_hook", args.hook_url, args.secret)


def list_hooks(args):
    if not args.gh_url and not args.jira_url:
        fail("Neither GitHub nor JIRA URL specified!")

    # user wants to list github hooks
    if args.gh_url:
        if not args.gh_token:
            fail("No GitHub token specified!")

        if not args.gh_org:
            fail("No GitHub organization specified!")

        github = ghlib.GitHub(args.gh_url, args.gh_token)

        if args.gh_repo:
            for h in github.getRepository(
                args.gh_org + "/" + args.gh_repo
            ).list_hooks():
                print(json.dumps(h, indent=4))
        else:
            for h in github.list_org_hooks(args.gh_org):
                print(json.dumps(h, indent=4))

    # user wants to list JIRA hooks
    if args.jira_url:
        if not args.jira_user or not args.jira_token:
            fail("No JIRA credentials specified!")

        jira = jiralib.Jira(args.jira_url, args.jira_user, args.jira_token)

        for h in jira.list_hooks():
            print(json.dumps(h, indent=4))


def main():
    credential_base = argparse.ArgumentParser(add_help=False)
    credential_base.add_argument("--gh-org", help="GitHub organization")
    credential_base.add_argument("--gh-repo", help="GitHub repository")
    credential_base.add_argument(
        "--gh-url",
        help="API URL of GitHub instance",
    )
    credential_base.add_argument(
        "--gh-token",
        help="GitHub API token. Alternatively, the GH2JIRA_GH_TOKEN may be set.",
        default=os.getenv("GH2JIRA_GH_TOKEN"),
    )
    credential_base.add_argument("--jira-url", help="URL of JIRA instance")
    credential_base.add_argument("--jira-user", help="JIRA user name")
    credential_base.add_argument(
        "--jira-token",
        help="JIRA password. Alternatively, the GH2JIRA_JIRA_TOKEN may be set.",
        default=os.getenv("GH2JIRA_JIRA_TOKEN"),
    )
    credential_base.add_argument("--jira-project", help="JIRA project key")
    credential_base.add_argument("--jira-labels", help="JIRA bug label(s)")
    credential_base.add_argument(
        "--secret",
        help="Webhook secret. Alternatively, the GH2JIRA_SECRET may be set.",
        default=os.getenv("GH2JIRA_SECRET"),
    )

    direction_base = argparse.ArgumentParser(add_help=False)
    direction_base.add_argument(
        "--direction",
        help='Sync direction. Possible values are "gh2jira" (alert states have higher priority than issue states),'
        + '"jira2gh" (issue states have higher priority than alert states) and "both" (adjust in both directions)',
        default="both",
    )

    issue_state_base = argparse.ArgumentParser(add_help=False)
    issue_state_base.add_argument(
        "--issue-end-state",
        help="Custom end state (e.g. Closed) Done by default",
        default="Done",
    )
    issue_state_base.add_argument(
        "--issue-reopen-state",
        help="Custom reopen state (e.g. In Progress) To Do by default",
        default="To Do",
    )
    issue_state_base.add_argument(
        "--auto-transition",
        help="Enable automatic status transitions based on assignee (To Do <-> Waiting Fix)",
        action="store_true",
        default=True,
    )
    issue_state_base.add_argument(
        "--no-auto-transition",
        help="Disable automatic status transitions based on assignee",
        action="store_true",
        default=False,
    )
    issue_state_base.add_argument(
        "--assign-secret-author",
        help="Assign secret scanning issues to the person who introduced the secret (requires additional GitHub API calls)",
        action="store_true",
        default=False,
    )

    parser = argparse.ArgumentParser(prog="gh2jira")
    subparsers = parser.add_subparsers()

    # serve
    serve_parser = subparsers.add_parser(
        "serve",
        parents=[credential_base, direction_base, issue_state_base],
        help="Spawn a webserver which keeps GitHub alerts and JIRA tickets in sync",
        description="Spawn a webserver which keeps GitHub alerts and JIRA tickets in sync",
    )
    serve_parser.add_argument(
        "--port", help="The port the server will listen on", default=5000
    )
    serve_parser.set_defaults(func=serve)

    # sync
    sync_parser = subparsers.add_parser(
        "sync",
        parents=[credential_base, direction_base, issue_state_base],
        help="Synchronize GitHub alerts and JIRA tickets for a given repository",
        description="Synchronize GitHub alerts and JIRA tickets for a given repository",
    )
    sync_parser.add_argument(
        "--state-file",
        help="File holding the current states of all alerts. The program will create the"
        + " file if it doesn't exist and update it after each run.",
        default=None,
    )
    sync_parser.add_argument(
        "--state-issue",
        help="The key of the issue holding the current states of all alerts. The program "
        + 'will create the issue if "-" is given as the argument. The issue will be '
        + "updated after each run.",
        default=None,
    )
    sync_parser.set_defaults(func=sync)

    # update-assignees
    update_assignees_parser = subparsers.add_parser(
        "update-assignees",
        parents=[credential_base, issue_state_base],
        help="Update assignees for existing JIRA issues to prioritize maintainers",
        description="Update assignees for existing JIRA issues to prioritize maintainers",
    )
    update_assignees_parser.set_defaults(func=update_assignees)

    # hooks
    hooks = subparsers.add_parser(
        "hooks",
        help="Manage JIRA and GitHub webhooks",
        description="Manage JIRA and GitHub webhooks",
    )

    hooks_subparsers = hooks.add_subparsers()

    # list hooks
    hooks_list = hooks_subparsers.add_parser(
        "list",
        parents=[credential_base],
        help="List existing GitHub or JIRA webhooks",
        description="List existing GitHub or JIRA webhooks",
    )
    hooks_list.set_defaults(func=list_hooks)

    # install hooks
    hooks_install = hooks_subparsers.add_parser(
        "install",
        parents=[credential_base],
        help="Install existing GitHub or JIRA webhooks",
        description="Install GitHub or JIRA webhooks",
    )
    hooks_install.add_argument("--hook-url", help="Webhook target url")
    hooks_install.add_argument(
        "--insecure-ssl",
        action="store_true",
        help="Install GitHub hook without SSL check",
    )
    hooks_install.set_defaults(func=install_hooks)

    # check hooks
    hooks_check = hooks_subparsers.add_parser(
        "check",
        parents=[credential_base],
        help="Check that hooks are installed properly",
        description="Check that hooks are installed properly",
    )
    hooks_check.set_defaults(func=check_hooks)

    def print_usage(args):
        print(parser.format_usage())

    parser.set_defaults(func=print_usage)
    args = parser.parse_args()

    # run the given action
    args.func(args)


main()
