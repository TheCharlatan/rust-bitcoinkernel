#!/bin/bash
#
# Script to find kernel: commits from the latest git subtree squashed merge
#
# This script automatically detects the latest squashed subtree merge commit,
# extracts the commit range from the squash message, then finds all kernel:
# prefixed commits in that range.
#
# Usage: ./check_subtree_kernel_commits.sh
#
# The script looks for squashed subtree merges in: libbitcoinkernel-sys/bitcoin

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Hardcoded subtree directory
SUBTREE_DIR="libbitcoinkernel-sys/bitcoin"
# Hardcoded github url
GITHUB_URL="https://github.com/bitcoin/bitcoin"


# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${RED}Error: Not in a git repository${NC}"
    exit 1
fi

# Function to extract subtree upstream commit from a merge commit
extract_upstream_commit() {
    local commit_hash="$1"
    local commit_msg
    commit_msg=$(git log -1 --format=%B "$commit_hash")

    # Extract from squashed format: "Squashed 'path/' changes from START..END"
    # Extract the END part after ".."
    local upstream
    upstream=$(echo "$commit_msg" | sed -n "s/.*Squashed.*changes from [0-9a-f]\{12\}\.\.\([0-9a-f]\{12\}\).*/\1/p")

    echo "$upstream"
}

# Function to extract previous upstream commit from squashed merge
extract_previous_upstream() {
    local commit_hash="$1"
    local commit_msg
    commit_msg=$(git log -1 --format=%B "$commit_hash")

    # Extract from squashed format: "Squashed 'path/' changes from START..END"
    # Extract the START part before ".."
    local previous
    previous=$(echo "$commit_msg" | sed -n "s/.*Squashed.*changes from \([0-9a-f]\{12\}\)\.\..*/\1/p")

    echo "$previous"
}

# Function to get kernel commits in a range
get_kernel_commits() {
    local start_commit="$1"
    local end_commit="$2"

    git log "${start_commit}..${end_commit}" --grep="^kernel:" -i --oneline --no-merges 2>/dev/null || true
}

# Function to display kernel commits with details
display_kernel_commits() {
    local commits="$1"

    if [ -z "$commits" ]; then
        echo -e "${RED}No commits found with 'kernel:' prefix${NC}"
        return
    fi

    local count
    count=$(echo "$commits" | wc -l)
    echo -e "${GREEN}Found ${count} commit(s) with 'kernel:' prefix${NC}"
    echo ""

    echo "$commits" | while IFS= read -r line; do
        local commit_hash
        commit_hash=$(echo "$line" | awk '{print $1}')

        echo -e "${YELLOW}Commit: ${commit_hash}${NC}"

        # Get full commit message
        local full_message
        full_message=$(git log -1 --format=%B "$commit_hash")
        echo "Message: $full_message"

        # Get author and date
        local author
        author=$(git log -1 --format="%an" "$commit_hash")
        local date
        date=$(git log -1 --format="%ad" --date=short "$commit_hash")
        echo "Author: $author"
        echo "Date: $date"

        # Show files changed
        echo "Files changed:"
        git show --name-only --format="" "$commit_hash" | sed 's/^/  /'

        echo ""
        echo "---"
        echo ""
    done

    echo ""
    echo -e "${GREEN}Total: ${count} kernel-related commit(s)${NC}"
}

# Function to check merge
check_merge() {
    local merge_commit="$1"

    echo -e "${BLUE}Checking merge commit ${merge_commit:0:8}...${NC}"

    # Extract the upstream commit from the merge
    local upstream_commit
    upstream_commit=$(extract_upstream_commit "$merge_commit")

    # Extract the previous upstream commit from the merge
    local previous_upstream
    previous_upstream=$(extract_previous_upstream "$merge_commit")

    local compare_url="${GITHUB_URL}/compare/${previous_upstream}...${upstream_commit}"


    # Display range info
    local merge_date
    merge_date=$(git log -1 --format="%ai" "$merge_commit")
    echo ""
    echo -e "${GREEN}=== Subtree Merge Information ===${NC}"
    echo "Merge commit: ${merge_commit}"
    echo "Merge date: $merge_date"
    echo "Previous upstream: ${previous_upstream:0:8}"
    echo "New upstream: ${upstream_commit:0:8}"
    echo "Range: ${previous_upstream:0:8}..${upstream_commit:0:8}"
    echo ""
    echo -e "${BLUE}GitHub Compare:${NC}"
    echo "$compare_url"
    echo ""

    # Get kernel commits
    local kernel_commits
    kernel_commits=$(get_kernel_commits "$previous_upstream" "$upstream_commit")

    # Display results
    display_kernel_commits "$kernel_commits"
}

# Main execution
echo -e "${BLUE}Finding latest subtree merge for ${SUBTREE_DIR}...${NC}"

# Get the latest squashed merge commit
MERGE_COMMIT=$(git log -1 --format=%H --grep="Squashed.*'${SUBTREE_DIR}/'.*changes from")

if [ -z "$MERGE_COMMIT" ]; then
    echo -e "${RED}No subtree merge found for ${SUBTREE_DIR}${NC}"
    exit 1
fi

check_merge "$MERGE_COMMIT"
