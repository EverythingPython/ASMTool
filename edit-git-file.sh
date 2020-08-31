#!/bin/bash



# git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch .idea/BinCMP.iml' --prune-empty --tag-name-filter cat -- --all

# git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch .idea/*.xml' --prune-empty --tag-name-filter cat -- --all

# git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch data/*' --prune-empty --tag-name-filter cat -- --all

git filter-branch --force --index-filter 'git rm --cached --ignore-unmatch report.txt' --prune-empty --tag-name-filter cat -- --all