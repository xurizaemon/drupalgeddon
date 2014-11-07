<?php

/**
 * Check to see if there is a Drupal Security Update
 */
function outdated_version_check() {
  if (module_exists('update') === FALSE) {
    return array('Update module is disabled and Drupalgeddon cannot check for ' . 
      'Drupal Security Updates. Please check for a security update manually.' . 
      "\nYou are running Drupal " . VERSION .
      "\nhttps://www.drupal.org/node/3060/release?api_version%5B%5D=103");
  }

  $updates = update_get_available(TRUE);
  $updates = update_calculate_project_data($updates);

  // No available Drupal security updates
  if (empty($updates['drupal']) === TRUE ||
      empty($updates['drupal']['security updates']) === TRUE) { return; }

  $latest_secure = $updates['drupal']['security updates'][0]['version'];

  return array('Drupal ' . VERSION . ' has security vulnerabilities. Please ' .
    "update to $latest_secure or higher.");
}
