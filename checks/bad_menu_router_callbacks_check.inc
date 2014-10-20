<?php

/**
 * https://gist.github.com/joshkoenig/70ebb6af239dd95f3ce6
 * Check for menu_router attacks with malicious callbacks
 */
function bad_menu_router_callbacks_check() {
  $bad_callbacks = array(
    'assert',
    'file_put_contents',
    'eval'
  );
  foreach ($bad_callbacks as $bad_callback) {
    if ($result = db_query('SELECT mr.path FROM {menu_router} mr WHERE mr.access_callback = :cb', array(':cb' => $bad_callback))) {
      if ($user = $result->fetchObject()) {
        $res[] = t('Menu router @name discovered.', array('@name' => $bad_callback));
      }
    }
  }
  if (!empty($res)) {
    return $res;
  }
}
