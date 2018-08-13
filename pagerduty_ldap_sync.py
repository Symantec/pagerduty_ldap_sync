#!/usr/bin/env python

import json
import logging
import ldap
import os
import pygerduty.v2
import requests
import time
from ldap.controls.libldap import SimplePagedResultsControl
from pagerduty_user_delete import main as lfepp_delete_pagerduty_user

logger = logging.getLogger('pagerduty_ldap_sync')

# configurable as a float from 0 to 1
# will raise exception if you try to delete more slack users than 20% of the total slack users.
# This is in case ldap returns an empty list, or a truncated list.
# We don't want LDAP issues to cause everyone in slack to be deleted.
max_delete_failsafe = float(os.environ.get('PAGERDUTY_MAX_DELETE_FAILSAFE', 0.2))
slack_token         = os.environ.get('SLACK_TOKEN')
slack_icon_emoji    = os.environ.get('SLACK_ICON_EMOJI', ':scream_cat:')
# pagerduty vars
pagerduty_api_key   = os.environ.get('PAGERDUTY_API_KEY')
pagerduty_url       = os.environ.get('PAGERDUTY_URL')
# 'ldaps://ad.example.com:636', make sure you always use ldaps
ad_url              = os.environ.get('AD_URL')
ad_basedn           = os.environ.get('AD_BASEDN')
ad_binddn           = os.environ.get('AD_BINDDN')
ad_bindpw           = os.environ.get('AD_BINDPW')
ad_email_attribute  = os.environ.get('AD_EMAIL_ATTRIBUTE', 'mail')
# note: make sure you only search the directory for active employees. This step is critical to the sync process.
search_flt          = os.environ.get('AD_SEARCH_FILTER_FOR_ACTIVE_EMPLOYEES_ONLY')
page_size           = 5000
trace_level         = 0
# '["uid", "active_employee_attribute"]'
searchreq_attrlist  = json.loads(os.environ.get('AD_SEARCHREQ_ATTRLIST'))
sync_run_interval   = 14400.0


def get_all_pagerduty_users(pagerduty):
  all_pagerduty_users = []
  for pagerduty_user in pagerduty.users.list():
    pagerduty_user_json = pagerduty_user.to_json()
    all_pagerduty_users.append((pagerduty_user_json['email'], pagerduty_user_json['id']))
  return all_pagerduty_users


def get_all_active_ad_users():
  l = ldap.initialize(ad_url, trace_level=trace_level)
  l.set_option(ldap.OPT_REFERRALS, 0)
  l.set_option(ldap.OPT_X_TLS_DEMAND, True)
  l.protocol_version = 3
  l.simple_bind_s(ad_binddn, ad_bindpw)

  req_ctrl              = SimplePagedResultsControl(True,size=page_size,cookie='')
  known_ldap_resp_ctrls = {SimplePagedResultsControl.controlType:SimplePagedResultsControl}
  attrlist              = [s.encode('utf-8') for s in searchreq_attrlist]
  msgid                 = l.search_ext(ad_basedn, ldap.SCOPE_SUBTREE, search_flt, attrlist=attrlist, serverctrls=[req_ctrl])
  all_ad_users          = {}
  pages                 = 0

  while True:
    pages += 1
    rtype, rdata, rmsgid, serverctrls = l.result3(msgid,resp_ctrl_classes=known_ldap_resp_ctrls)
    for entry in rdata:
      if 'mail' in entry[1] and entry[1]['mail'][0]:
        email = entry[1]['mail'][0]
        all_ad_users[email.lower()] = True
    pctrls = [
      c
      for c in serverctrls
      if c.controlType == SimplePagedResultsControl.controlType
    ]
    if pctrls:
      if pctrls[0].cookie:
        # Copy cookie from response control to request control
        req_ctrl.cookie = pctrls[0].cookie
        msgid = l.search_ext(ad_basedn, ldap.SCOPE_SUBTREE, search_flt, attrlist=attrlist, serverctrls=[req_ctrl])
      else:
        break
    else:
      raise Exception("AD query Warning: Server ignores RFC 2696 control.")
      break
  l.unbind_s()
  return all_ad_users


def slack_message_pagerduty_channel(message):
  message = '```%s```' % message
  payload = {
    'token'     : slack_token,
    'channel'   : '#pagerduty',
    'text'      : message,
    'username'  : 'pagerduty reaper',
    'icon_emoji': slack_icon_emoji
  }
  http_response = requests.post(url=slack_token, data=json.dumps(payload))
  http_response.raise_for_status()
  return True


def get_pagerduty_users_not_in_ldap(all_pagerduty_users, all_active_ldap_users):
  pagerduty_users_not_in_ldap = []
  for pagerduty_user in all_pagerduty_users:
    if pagerduty_user[0] not in all_active_ldap_users:
      pagerduty_users_not_in_ldap.append(pagerduty_user)
  return pagerduty_users_not_in_ldap


def delete_pagerduty_user(pagerduty_api_key, pagerduty_user_email):
  result = lfepp_delete_pagerduty_user(pagerduty_api_key, pagerduty_user_email, 'noreply@example.com')
  return result


def remove_white_list_users(pagerduty_users_to_be_deleted):
    pagerduty_users = []
    white_list_users = os.environ.get('PD_WHITE_LIST_USERS', '').lower().split(',')
    for pagerduty_user_to_be_deleted in pagerduty_users_to_be_deleted:
        if pagerduty_user_to_be_deleted[0] in white_list_users:
            continue
        else:
            pagerduty_users.append(pagerduty_user_to_be_deleted)
    return pagerduty_users


def sync_pagerduty_ldap():
  logger.info('Looking for pagerduty users to delete that do not exist or are not active in corp LDAP')
  pagerduty                     = pygerduty.v2.PagerDuty(pagerduty_api_key)
  all_pagerduty_users           = get_all_pagerduty_users(pagerduty)
  all_active_ldap_users         = get_all_active_ad_users()
  pagerduty_users_to_be_deleted = get_pagerduty_users_not_in_ldap(all_pagerduty_users, all_active_ldap_users)
  pagerduty_users_to_be_deleted = remove_white_list_users(pagerduty_users_to_be_deleted)
  percent_slack_users_deleted   = float(len(pagerduty_users_to_be_deleted)) / len(all_pagerduty_users)
  # raise exception if we try to delete too many users as a failsafe.

  if percent_slack_users_deleted > max_delete_failsafe:
    raise Exception('The failsafe threshold for deleting too many slack users was reached. No users were deleted.')

  # After the failsafe is over, go through and delete all the users who should be deleted.
  for pagerduty_user in pagerduty_users_to_be_deleted:
    logger.debug('Starting the deletion of pagerduty user: %s') % pagerduty_user[0]
    slack_message_pagerduty_channel(delete_pagerduty_user(pagerduty_api_key, pagerduty_user[0]))


if __name__ == '__main__':
  logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
  logging.getLogger('requests').setLevel(logging.ERROR)
  error_counter = 0
  while True:
    try:
      sync_pagerduty_ldap()
      error_counter = 0
    except Exception as error:
      logger.exception(error)
      # if we regularly have exceptions, let slack owners know about it once per day.
      error_counter += 1
      if error_counter % 48 == 4:
        pagerduty_sync_error = 'This exception is being sent to slack since it is the 4th one is a row. %s' % error
        slack_message_pagerduty_channel(pagerduty_sync_error)
    sleep_message = 'Sleeping for %s minutes' % str(int(sync_run_interval) / 60)
    logger.info(sleep_message)
    time.sleep(sync_run_interval)
