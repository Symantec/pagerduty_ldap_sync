#Delete pagerduty users not active in your LDAP instance

##How to use with just docker.

- docker build -t slack_ldap_sync .
- docker run -it -e SLACK_MAX_DELETE_FAILSAFE="0.2" \
-e PAGERDUTY_API_KEY="foobarbazqux"
-e SLACK_TOKEN="xoxp-exampletokenfoobarbazqux" \
-e SLACK_SYNC_RUN_INTERVAL="1800" \
-e AD_URL="ldaps://ldap.example.com:636" \
-e AD_BASEDN="ou=people,DC=example,DC=com" \
-e AD_SEARCH_FILTER_FOR_ACTIVE_EMPLOYEES_ONLY='(&(uid=*)(employee_status=active))' \
-e AD_BINDDN="foo\user_name" \
-e AD_BINDPW="password" \
-e AD_SEARCHREQ_ATTRLIST='["mail", "active_employee_attribute=True"]' \
-e AD_EMAIL_ATTRIBUTE="mail" 


##How to use with docker/openshift

- edit the source.example and set the variables how you want
- oc new-project pagerduty-ldap-sync
- oc create secret generic pagerduty-ldap-secrets --from-file=source.example
- run ./deploy.sh to deploy to openshift
