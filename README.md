Drupalgeddon Checks
==================

I want a quick way of checking for known attack signatures on multiple
sites across a set of servers. Making a Drush command is a quick way
to enable this.

A signature-based malware detector in PHP is probably a bad thing :)
but this might be a useful tool for this situation, so here it is.

Oh, feel free to fork / add / extend checks in the checks directory -
one check per file, match the filename and function name. You'll see.

(This probably grew out of some idle thinking about adding our own
custom checks to Archimedes / Aegir setup.)

Usage
-----

* Install this to ~/.drush or other Drush include
* Have some aliases for all your sites
* `drush -y @sites drupalgeddon-test`
