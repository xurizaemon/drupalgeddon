<?php

/**
 * A check for bad users.
 * https://gist.github.com/joshkoenig/dbb543c02198330cbf87
 */
function bad_users_check() {
  $bad_users = array(
    'configure',
    'system',
    'n0n0x',
    'chris.burgess',
  );
  foreach ($bad_users as $bad_user) {
    if ($result = db_query('SELECT n.uid FROM {users} n WHERE n.name = :name', array(':name' => $bad_user))) {
      if ($user = $result->fetchObject()) {
        $res[] = t('User "@name" discovered.', array('@name' => $bad_user));
      }
    }
  }
  if (!empty($res)) {
    return $res;
  }
}
