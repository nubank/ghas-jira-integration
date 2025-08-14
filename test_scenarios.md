# Test Scenarios for GHAS-Jira Integration

## Scenario 1: Alert Reappearance (Reencarnação de Alerts)

### Initial Setup
1. **Create a Code Scanning Alert in GitHub**
   - Alert state: `"open"`
   - Alert number: e.g., `123`
   - Repository: `org/repo`

2. **First Sync - Create Initial Issue**
   - Run sync to create initial Jira issue
   - Expected: Issue created in "To Do" state
   - Issue gets assigned and moves to "Waiting Fix"

3. **Fix the Alert**
   - GitHub alert state changes to: `"fixed"`
   - Run sync
   - Expected: Jira issue transitions to "Done"

### Test the Reappearance Scenario

4. **Simulate Alert Reappearance**
   - GitHub alert state: `"open"` (reappeared)
   - Webhook event: `"appeared_in_branch"`
   - Branch: `"feature/new-code"`
   
   **Expected Results:**
   - ✅ New Jira issue created with title suffix: "- Reappeared in branch FEATURE/NEW-CODE"
   - ✅ New issue description contains: "*Reappeared in branch FEATURE/NEW-CODE*"
   - ✅ Original "Done" issue remains untouched
   - ✅ New issue starts in "To Do" state and gets assigned

### Manual Test Commands

```bash
# Test via CLI sync
./gh2jira sync \
  --gh-url "https://api.github.com" \
  --gh-token "YOUR_TOKEN" \
  --gh-org "org" \
  --gh-repo "repo" \
  --jira-url "YOUR_JIRA_URL" \
  --jira-user "user" \
  --jira-token "token" \
  --jira-project "PROJECT" \
  --direction "gh2jira"
```

### Webhook Test Payload

```json
{
  "action": "appeared_in_branch",
  "alert": {
    "number": 123,
    "state": "open",
    "html_url": "https://github.com/org/repo/security/code-scanning/123"
  },
  "repository": {
    "full_name": "org/repo"
  },
  "ref": "refs/heads/feature/new-code"
}
```

---

## Scenario 2: Multiple Issues per Alert (Múltiplas Issues)

### Setup Multiple Issues for Same Alert

1. **Create First Issue** (manually in Jira)
   - Project: YOUR_PROJECT
   - Issue Type: "Vulnerability - General"
   - Description must contain:
   ```
   REPOSITORY_NAME=org/repo
   ALERT_TYPE=Alert
   ALERT_NUMBER=456
   REPOSITORY_KEY=<repo_key>
   ALERT_KEY=<alert_key>
   ```
   - Status: "Done" (closed)

2. **Create Second Issue** (manually in Jira)
   - Same metadata as above
   - Status: "To Do" (open)

3. **Create Third Issue** (manually in Jira)
   - Same metadata as above
   - Status: "Waiting Fix" (open)

### Test Multiple Issues Cleanup

4. **Run Sync**
   - GitHub alert state: `"open"`
   - Alert number: `456`

   **Expected Results:**
   - ✅ Only ONE issue remains (the newest open one)
   - ✅ Issues are sorted by ID (newest first)
   - ✅ Priority: newest open issue > newest closed issue
   - ✅ Deleted issues: older duplicates

### Code Logic Reference

From `sync.py` lines 148-167:
```python
if len(issues) > 1:
    # Sort by ID descending (newest first)
    issues.sort(key=lambda i: -int(i.id()))
    
    # Filter for open issues first
    open_issues = [i for i in issues if i.get_state()]
    
    # Keep newest open issue, or newest issue if none open
    if open_issues:
        keep_issue = open_issues[0]
    else:
        keep_issue = issues[0]
        
    # Delete all others
    for i in issues:
        if i.id() != keep_issue.id():
            i.delete()
```

---

## Complete Test Matrix

| Scenario | GitHub Alert State | Jira Issues | Expected Behavior |
|----------|-------------------|-------------|-------------------|
| **Reappearance** | `"open"` (reappeared) | 1 issue "Done" | Create NEW issue, keep old |
| **Multiple Open** | `"open"` | 3 issues (2 open, 1 closed) | Keep newest open, delete others |
| **Multiple Closed** | `"fixed"` | 3 issues (all closed) | Keep newest closed, delete others |
| **Mixed States** | `"open"` | 2 open, 1 closed | Keep newest open, delete others |

---

## Detailed Test Steps

### For Alert Reappearance:

```bash
# Step 1: Initial sync (creates first issue)
curl -X POST http://localhost:5000/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: code_scanning_alert" \
  -d '{
    "action": "created",
    "alert": {"number": 123, "state": "open"},
    "repository": {"full_name": "org/repo"}
  }'

# Step 2: Fix alert (closes issue)
curl -X POST http://localhost:5000/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: code_scanning_alert" \
  -d '{
    "action": "fixed",
    "alert": {"number": 123, "state": "fixed"},
    "repository": {"full_name": "org/repo"}
  }'

# Step 3: Alert reappears (creates new issue)
curl -X POST http://localhost:5000/github \
  -H "Content-Type: application/json" \
  -H "X-GitHub-Event: code_scanning_alert" \
  -d '{
    "action": "appeared_in_branch",
    "alert": {"number": 123, "state": "open"},
    "repository": {"full_name": "org/repo"},
    "ref": "refs/heads/feature/new-code"
  }'
```

### For Multiple Issues:

1. **Create 3 manual Jira issues with same alert metadata**
2. **Run sync via CLI or webhook**
3. **Verify only 1 issue remains**

---

## Verification Checklist

### After Reappearance Test:
- [ ] 2 total issues exist for the same alert
- [ ] Original issue status = "Done"
- [ ] New issue title contains "- Reappeared in branch X"
- [ ] New issue description contains reappearance context
- [ ] New issue has proper assignee

### After Multiple Issues Test:
- [ ] Only 1 issue remains
- [ ] Remaining issue is the newest open one (highest ID)
- [ ] Other issues were deleted
- [ ] No duplicate issues for same alert

### Log Messages to Look For:

```
# Reappearance
"Alert 123 in org/repo reappeared in branch FEATURE/NEW-CODE. Creating new ticket while preserving completed ones."

# Multiple Issues Cleanup  
"Sort issues, keeping the newest active ones first"
"Delete all other issues except the one we're keeping"
```

This test matrix covers both scenarios comprehensively and provides clear expected outcomes for validation.
