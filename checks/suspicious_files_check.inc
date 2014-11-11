<?php
/**
 * @file
 * Check for potentially malicious files.
 */

/**
 * A check for potentially malicious files placed by the web server.
 * @link https://www.drupal.org/node/2360269
 */
function suspicious_files_check() {
  $result = suspicious_files_check_query();
  $res = array();
  if (!empty($result)) {
    foreach ($result as $file) {
      $res[] = t('Suspicious file "@file" discovered.', array(
        '@file' => $file,
      ));
    }
  }
  if (!empty($res)) {
    return $res;
  }
}

/**
 * Gather data for bad roles check.
 *
 * @return array
 *   Role names keyed by role id.
 */
function suspicious_files_check_query() {
  $found_files = file_scan_directory('.', '#.*\.php#', array('callback' => '_suspicious_files_callback_sites'));
  foreach ($found_files as $found_file) {
    if (!preg_match('#/(sites|profiles)/#', $found_file->uri)) {
      $files[] = realpath(DRUPAL_ROOT . DIRECTORY_SEPARATOR . $found_file->uri);
    }
  }

  $known_files = _suspicious_files_whitelist();
  foreach ($files as $file) {
    if (is_array($known_files) && !in_array($file, $known_files)) {
      // Exceptions to avoid too many false positives.
      if (stristr($file, '/sites/') === FALSE &&                    // Too many false positives.
          stristr($file, '/data/all/') === FALSE &&                 // Valid BOA path.
          stristr($file, '/data/disk/all/') === FALSE &&            // Valid BOA path.
          stristr($file, '/drushrc.php') === FALSE &&               // Valid Drush file.
          stristr($file, '/js.php') === FALSE &&                    // Valid BOA file/symlink.
          stristr($file, '/local.settings.php') === FALSE &&        // Valid Aegir file.
          stristr($file, '/modules/o_contrib_seven/') === FALSE &&  // Valid BOA path.
          stristr($file, '/rtoc.php') === FALSE &&                  // Valid BOA file.
          stristr($file, '/solr.php') === FALSE &&                  // Valid BOA file.
          stristr($file, '/themes/rubik/') === FALSE &&             // Valid BOA path.
          stristr($file, '/themes/tao/') === FALSE &&               // Valid BOA path.
          stristr($file, '/FirePHPCore/') === FALSE) {              // Whitelist FirePHPCore.
        $return[] = $file;
      }
    }
  }
  if (!empty($return)) {
    return $return;
  }
}

/**
 * List of files in a clean Drupal 7.33 install.
 */
function _suspicious_files_whitelist() {
  // Use correct hash for latest core (note: tree hash, not commit hash) from:
  // http://cgit.drupalcode.org/drupal/commit/?id=4ba5f184c69306da0e30260890f01ea0694af274
  $tree_list_url = 'https://github.com/drupal/drupal/tree-list/a27ea4ac2112bc9c70e5cf989b87b545ef501813';

  // Filename => array of valid sha1 hashes.
  $extra_whitelist = array(
    // A file removed from Drupal 7.29.
    'modules/help/help.api.php' => array(
      // 7.12.
      '6fab6bbb415ff429cfd5575820907a3fbb7d01ad',
      // 7.2.
      '187eff591132ab334159402a273d7d174823b197',
      // 7.0.
      'a73b016eff898e85ecd67663f2e735d9580e4cf8',
    ),
  );
  if ($response = drupal_http_request($tree_list_url)) {
    if ($json = json_decode($response->data)) {
      foreach ($json->paths as $path) {
        $paths[] = realpath(DRUPAL_ROOT . '/' . $path);
      }

      foreach ($extra_whitelist as $path => $sha1sums) {
        $full_path = realpath(DRUPAL_ROOT . '/' . $path);
        if (file_exists($full_path) && in_array(sha1_file($full_path), $sha1sums)) {
          $paths[] = $full_path;
        }
      }

      return $paths;
    }
  }
}

/**
 * Callback to exclude sites/*.
 */
function _suspicious_files_callback_sites($file) {
  if (!preg_match('#./sites#', $file)) {
    return $file;
  }
}
