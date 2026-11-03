#!/usr/bin/env bash

# Rebase the preconf-tile branch onto origin/main and verify it.
#
# Keeps the preconf relay tile's branch current as new commits land on
# origin/main: fetch, rebase, then build the validators and the affected
# unit tests, and regenerate the metrics (the fork's metrics linter is
# stricter than upstream's, so drift in metrics.xml/types.py can break the
# generated artifacts).  If everything passes, push with --force-with-lease.
#
# Usage: contrib/preconf-tile-sync.sh [FLAGS]
#   --no-verify    Skip the build/test verification
#   --no-push      Stop after a successful rebase/verification, do not push
#   --skip-rebase  Skip fetch/rebase (e.g. after manually resolving a
#                  rebase conflict and running `git rebase --continue`),
#                  only run verification and push
#   --help, -h     Show this message and exit

set -euo pipefail
IFS=$'\n\t'

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." >/dev/null 2>&1 && pwd)
cd "$ROOT"

BRANCH=preconf-tile
UPSTREAM_REF=origin/main

VERIFY=1
PUSH=1
DO_REBASE=1

help() {
  sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
  case "$arg" in
    --no-verify)   VERIFY=0 ;;
    --no-push)     PUSH=0 ;;
    --skip-rebase) DO_REBASE=0 ;;
    --help|-h)     help; exit 0 ;;
    *) echo "error: unknown option: $arg (see --help)" >&2; exit 2 ;;
  esac
done

current=$(git branch --show-current)
if [[ "$current" != "$BRANCH" ]]; then
  echo "error: must run on $BRANCH (currently: ${current:-detached HEAD})" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
  echo "error: working tree has uncommitted changes; commit or stash first" >&2
  exit 1
fi

if [[ -d .git/rebase-merge || -d .git/rebase-apply ]]; then
  echo "error: a rebase is in progress" >&2
  echo "       finish it with 'git rebase --continue' (or 'git rebase --abort')," >&2
  echo "       then rerun: contrib/preconf-tile-sync.sh --skip-rebase" >&2
  exit 1
fi

# ---------------------------------------------------------------- fetch/rebase
if [[ "$DO_REBASE" == 1 ]]; then
  git fetch --quiet origin main

  if git merge-base --is-ancestor "$UPSTREAM_REF" HEAD; then
    echo "==> $BRANCH already contains $UPSTREAM_REF; no rebase needed"
  else
    ahead=$(git rev-list --count "$UPSTREAM_REF..HEAD")
    echo "==> Replaying $ahead local commit(s) onto $UPSTREAM_REF"
    if ! git rebase "$UPSTREAM_REF"; then
      echo
      echo "!! Rebase hit conflicts.  Conflicting files:"
      git diff --name-only --diff-filter=U | sed 's/^/     /'
      echo
      echo "   Known port deltas that may collide with upstream drift:"
      echo "     - keyguard role numbering (ROLE_PRECNF after ROLE_BAM)"
      echo "     - fork link names (dedup_resolv) and builder signatures"
      echo "     - fork metrics linter renames in metrics.xml + generated"
      echo "   Resolve, then:"
      echo "     git add <fixed files> && git rebase --continue"
      echo "   or abandon this rebase:"
      echo "     git rebase --abort"
      echo
      echo "   After continuing, rerun: contrib/preconf-tile-sync.sh --skip-rebase"
      exit 1
    fi
  fi
fi

# ------------------------------------------------------------------- verify
TESTS=(
  test_precnf_encode
  test_keyguard
  test_sign_tile
  test_bundle_client
  test_firedancer_topology_bam
  test_config_json
  test_config_parse
)

if [[ "$VERIFY" == 1 ]]; then
  # Best effort: some tests use huge pages and need a high MEMLOCK limit
  ulimit -l unlimited 2>/dev/null || true

  # The waker installs its epoll sets at fixed high fds (123500+, see
  # src/disco/waker/fd_waker.h), so the process fd limit must exceed them;
  # on this kernel a dup2() past RLIMIT_NOFILE fails with EBADF and the
  # test aborts.  Raise the soft limit if we can, then insist on the floor.
  WAKER_FD_FLOOR=124000
  ulimit -n unlimited 2>/dev/null || ulimit -n $(( WAKER_FD_FLOOR + 8192 )) 2>/dev/null || true
  fd_soft=$(ulimit -n); fd_hard=$(ulimit -Hn)
  if [[ "$fd_soft" =~ ^[0-9]+$ ]] && (( fd_soft < WAKER_FD_FLOOR )); then
    echo "error: test fd limit is $fd_soft (hard: $fd_hard) but the waker needs >= $WAKER_FD_FLOOR" >&2
    echo "       raise it in this shell first, e.g.:" >&2
    echo "         ulimit -n $(( WAKER_FD_FLOOR + 8192 ))" >&2
    echo "       or persistently: 'sudo prlimit --pid \$\$ --nofile=132192:132192' / limits.conf" >&2
    exit 1
  fi

  echo "==> Building validators and tests"
  make -j firedancer firedancer-dev "${TESTS[@]}"

  OBJDIR=$(make --silent objdir)

  # Regenerate metrics: the fork's linter is stricter than upstream's, so
  # upstream drift in metrics.xml/types.py can invalidate the artifacts.
  echo "==> Regenerating metrics"
  make -C src/disco/metrics metrics > /dev/null

  dirty=$(git status --porcelain --untracked-files=no)
  if [[ -n "$dirty" ]]; then
    echo "!! Metrics regeneration produced changes — review and commit them:"
    echo "$dirty" | sed 's/^/     /'
    echo "   Then rerun: contrib/preconf-tile-sync.sh --skip-rebase"
    exit 1
  fi

  echo "==> Running unit tests"
  failed=0
  for t in "${TESTS[@]}"; do
    printf '   %-32s ' "$t"
    if ! "$OBJDIR/unit-test/$t" 2>&1 | sed 's/^/     | /'; then
      echo "FAIL"
      failed=1
    else
      echo "pass"
    fi
  done
  if [[ "$failed" != 0 ]]; then
    echo "!! One or more tests failed" >&2
    echo "   If the output mentions dup2/EBADF or mlock, check 'ulimit -n' and" >&2
    echo "   'ulimit -l' in this shell (see doc/testing.md)." >&2
    exit 1
  fi
fi

# ---------------------------------------------------------------------- push
if [[ "$PUSH" == 1 ]]; then
  echo "==> Pushing with --force-with-lease"
  git push --force-with-lease origin "$BRANCH"
else
  echo "==> Skipping push (--no-push)"
fi

echo "==> Done: $BRANCH is at $(git rev-parse --short HEAD) on top of $(git rev-parse --short "$UPSTREAM_REF")"
