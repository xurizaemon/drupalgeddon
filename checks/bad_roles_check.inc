<?php

/**
 * https://gist.github.com/joshkoenig/a941d1fd58c3383b7eb7
 * Check for bad roles!
 */
function bad_roles_check() {
  $bad_roles = array('megauser');
  foreach ($bad_roles as $bad_role) {
    if ($result = db_query('SELECT name FROM {role} r WHERE r.name = :name', array(':name' => $bad_role))) {
      if ($role = $result->fetchObject()) {
        $res[] = t('Role "@name" discovered.', array('@name' => $bad_role));
      }
    }
  }
  if (!empty($res)) {
    return $res;
  }
}
