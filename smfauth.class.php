<?php
/**
 * SMF authentication backend for Dokuwiki v 2009-07-17
 *
 * @license    Creative Commons BY
 * @author     David Frank <bitinn@gmail.com>
 * @version    0.3
 * @base       for Dokuwiki 2009-02-14 + SMF 1.1.10
 *
 * Provide as an alternative to smf.class.php
 * Does not introduce new trustExternal() to verify user,
 * merely extends a few funtions from mysql.class.php
 *
 * Pros:
 *  allow user registration within dokuwiki
 *  allow full user managerment within dokuwiki
 *  dokuwiki handles login, avoid old smf_api
 *  (which causes extensive amount of frustration)
 *
 * Cons:
 *  one-click login integration will be difficult
 *  (currently users have to login wiki/forum seperately)
 *  user deletion within dokuwiki is not complete
 *  (see additional comment on delUserRefs)
 */
define('DOKU_AUTH', dirname(__FILE__));
require_once(DOKU_AUTH.'/mysql.class.php');

  // !!! MODIFICATION REQUIRED !!!
  // Path to your SMF installation's Settings.php
  // absolute or relative should both be fine
  require_once('your-forum-path/Settings.php');

class auth_smfauth extends auth_mysql {

  // Constructor, set all necessary config strings.
  function auth_smfauth(){
	global $conf;
	// variables from SMF Settings.php
	global $db_server;
	global $db_name;
	global $db_user;
	global $db_passwd;
	global $db_prefix;
	
	// pass variables into config
	$conf['auth']['mysql']['server']   = $db_server;
	$conf['auth']['mysql']['user']     = $db_user;
	$conf['auth']['mysql']['password'] = $db_passwd;
	$conf['auth']['mysql']['database'] = $db_name;
	
	// as SMF uses SHA1(concat(username, password))
	$conf['auth']['mysql']['forwardClearPass'] = 1;

  // table to lock during multitable operation,
  // see mysql.conf.php for further infos.
  $conf['auth']['mysql']['TablesToLock']=
  array("${db_prefix}membergroups", "${db_prefix}membergroups AS g", "${db_prefix}members", "${db_prefix}members AS u");

    // some configs are copied directly from official wiki.
    // wiki.splitbrain.org/wiki:auth:mysql_smf
    // more info to be found in mysql.conf.php
    $conf['auth']['mysql']['checkPass']   = "SELECT passwd
                                             FROM ${db_prefix}members
                                             WHERE memberName = '%{user}'
                                             AND passwd = SHA1(concat(LOWER('%{user}'), '%{pass}'))";
 
    $conf['auth']['mysql']['getUserInfo'] = "SELECT passwd AS pass, realName AS name, emailAddress AS mail
                                             FROM ${db_prefix}members
                                             WHERE memberName = '%{user}'";
 
    // `group` here, don't forget the quotes!
    // trying to get all groups.
    // concat trick to correctly test an ID group
    $conf['auth']['mysql']['getGroups']   = "SELECT groupName AS `group`
                                             FROM ${db_prefix}membergroups g, ${db_prefix}members u
                                             WHERE u.memberName = '%{user}'
                                             AND (concat(',',u.additionalGroups,',') LIKE concat('%,',g.ID_GROUP,',%') OR u.ID_GROUP = g.ID_GROUP)";

    // using both ID_GROUP and additionalGroups in query
    $conf['auth']['mysql']['getUsers']    = "SELECT DISTINCT memberName AS user
                                             FROM ${db_prefix}members AS u
                                             LEFT JOIN ${db_prefix}membergroups AS g ON (concat(',',u.additionalGroups,',') LIKE concat('%,',g.ID_GROUP,',%') OR u.ID_GROUP=g.ID_GROUP)";

    $conf['auth']['mysql']['FilterLogin'] = "u.memberName LIKE '%{user}'";
    $conf['auth']['mysql']['FilterName']  = "u.realName LIKE '%{name}'";
    $conf['auth']['mysql']['FilterEmail'] = "u.emailAddress LIKE '%{email}'";
    $conf['auth']['mysql']['FilterGroup'] = "g.groupName LIKE '%{group}'";
    $conf['auth']['mysql']['SortOrder']   = "ORDER BY u.memberName";

    // default group should be 0, fixed in v0.2
    // additionalGroups no longer has default value, fixed
    $conf['auth']['mysql']['addUser']     = "INSERT INTO ${db_prefix}members
                                             (memberName, dateRegistered, ID_GROUP, realName, passwd, emailAddress, hideEmail, additionalGroups)
                                             VALUES ('%{user}', UNIX_TIMESTAMP(), '0', '%{name}', SHA1(concat(LOWER('%{user}'), '%{pass}')), '%{email}', '1', '10')";

    $conf['auth']['mysql']['addGroup']    = "INSERT INTO ${db_prefix}membergroups (groupName, stars) VALUES ('%{group}','1#star.gif')";

    // changed in v0.2 to use additionalGroups
    $conf['auth']['mysql']['addUserGroup']= "UPDATE ${db_prefix}members
                                             SET additionalGroups = TRIM(BOTH ',' FROM concat(additionalGroups,',','%{gid}'))
										     WHERE ID_MEMBER = '%{uid}'";

    $conf['auth']['mysql']['delGroup']    = "DELETE FROM `${db_prefix}membergroups` WHERE `ID_GROUP` = '%{gid}' LIMIT 1";
																 
    $conf['auth']['mysql']['getUserID']   = "SELECT ID_MEMBER AS id FROM ${db_prefix}members WHERE memberName = '%{user}' LIMIT 1";

    $conf['auth']['mysql']['delUser']     = "DELETE FROM ${db_prefix}members
                                             WHERE ID_MEMBER = '%{uid}' LIMIT 1";
										 
    // long ref list taken from Sources/Subs-Members.php, not a perfect port;
    // missing features such as avatar removal, buddylist cleaning & calendar update etc.
    // use SMF's interface as a preferable alternative. 
    $conf['auth']['mysql']['delUserRefs'] = "UPDATE ${db_prefix}messages SET ID_MEMBER = 0, posterEmail = '' WHERE ID_MEMBER = '%{uid}';
                                             UPDATE ${db_prefix}polls SET ID_MEMBER = 0 WHERE ID_MEMBER = '%{uid}';
                                             UPDATE ${db_prefix}topics SET ID_MEMBER_STARTED = 0 WHERE ID_MEMBER_STARTED = '%{uid}';
                                             UPDATE ${db_prefix}topics SET ID_MEMBER_UPDATED = 0 WHERE ID_MEMBER_UPDATED = '%{uid}';
                                             UPDATE ${db_prefix}log_actions SET ID_MEMBER = 0 WHERE ID_MEMBER = '%{uid}';
                                             UPDATE ${db_prefix}log_banned SET ID_MEMBER = 0 WHERE ID_MEMBER = '%{uid}';
                                             UPDATE ${db_prefix}log_errors SET ID_MEMBER = 0 WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_boards WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_karma WHERE ID_TARGET = '%{uid}' OR ID_EXECUTOR = '%{uid}';
                                             DELETE FROM ${db_prefix}log_mark_read WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_notify WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_online WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_polls WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}log_topics WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}collapsed_categories WHERE ID_MEMBER = '%{uid}';
                                             UPDATE ${db_prefix}personal_messages SET ID_MEMBER_FROM = 0 WHERE ID_MEMBER_FROM = '%{uid}';
                                             DELETE FROM ${db_prefix}moderators WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}ban_items WHERE ID_MEMBER = '%{uid}';
                                             DELETE FROM ${db_prefix}themes WHERE ID_MEMBER = '%{uid}'";

    $conf['auth']['mysql']['updateUser']  = "UPDATE ${db_prefix}members SET";
    $conf['auth']['mysql']['UpdateLogin'] = "memberName = '%{user}'";

    // this is reason we can't use mysql.class.php directly,
    // miss a %{user} filter in original _updateUserInfo funtion
    $conf['auth']['mysql']['UpdatePass']  = "passwd = SHA1(concat(LOWER('%{user}'), '%{pass}'))";
    $conf['auth']['mysql']['UpdateEmail'] = "emailAddress = '%{email}'";
    $conf['auth']['mysql']['UpdateName']  = "realName = '%{name}'";
    $conf['auth']['mysql']['UpdateTarget']= "WHERE ID_MEMBER = '%{uid}'";

    // now taken care of SMF's additionalGroups as well.
    $conf['auth']['mysql']['delUserGroup']= "UPDATE ${db_prefix}members
                                             SET additionalGroups = TRIM(BOTH ',' REPLACE(concat(',',additionalGroups,','), concat(',','%{gid}',','), ','))
                                             WHERE ID_MEMBER = '%{uid}'";

    $conf['auth']['mysql']['getGroupID']  = "SELECT ID_GROUP AS id FROM ${db_prefix}membergroups g WHERE g.groupName = '%{group}'";
	
	// added for utf-8 query support
	$conf['auth']['mysql']['charset'] = "utf8";

	// let auth_mysql() do the rest.
	$this->auth_mysql();
	
  }

  //replace mysql.class.php's original function.
  function _updateUserInfo($changes, $uid) {
    $sql  = $this->cnf['updateUser']." ";
    $cnt = 0;
    $err = 0;
    global $db_prefix;

    //hacked to obtain new username beforehand.
    if(!$changes['user']) {
	    $user = mysql_fetch_array(mysql_query("SELECT DISTINCT memberName FROM ".$db_prefix."members WHERE ID_MEMBER = '$uid'"));
    } else {
	    $user['memberName'] = $changes['user'];
    }
	  
      if($this->dbcon) {
        foreach ($changes as $item => $value) {
          if ($item == 'user') {
            if (($this->_getUserID($changes['user']))) {
              $err = 1; /* new username already exists */
              break;    /* abort update */
            }
            if ($cnt++ > 0) $sql .= ", ";
            $sql .= str_replace('%{user}',$value,$this->cnf['UpdateLogin']);
          } else if ($item == 'name') {
            if ($cnt++ > 0) $sql .= ", ";
            $sql .= str_replace('%{name}',$value,$this->cnf['UpdateName']);
          } else if ($item == 'pass') {
            if (!$this->cnf['forwardClearPass'])
              $value = auth_cryptPassword($value);
            if ($cnt++ > 0) $sql .= ", ";
            $sql .= str_replace('%{pass}',$value,$this->cnf['UpdatePass']);
            //see $conf['auth']['mysql']['UpdatePass'] for explanation
            $sql = str_replace('%{user}',$user['memberName'],$sql);
          } else if ($item == 'mail') {
            if ($cnt++ > 0) $sql .= ", ";
            $sql .= str_replace('%{email}',$value,$this->cnf['UpdateEmail']);
          }
        }

        if ($err == 0) {
          if ($cnt > 0) {
            $sql .= " ".str_replace('%{uid}', $uid, $this->cnf['UpdateTarget']);
            if(get_class($this) == 'auth_mysql') $sql .= " LIMIT 1"; //some PgSQL inheritance comp.
            $this->_modifyDB($sql);
          }
          return true;
        }
      }
    return false;
  }

    //replace mysql.class.php's original function.
    function _openDB() {
      if (!$this->dbcon) {
        $con = @mysql_connect ($this->cnf['server'], $this->cnf['user'], $this->cnf['password']);
        if ($con) {
          if ((mysql_select_db($this->cnf['database'], $con))) {
            if ((preg_match("/^(\d+)\.(\d+)\.(\d+).*/", mysql_get_server_info ($con), $result)) == 1) {
              $this->dbver = $result[1];
              $this->dbrev = $result[2];
              $this->dbsub = $result[3];
            }
            $this->dbcon = $con;
            if(!empty($this->cnf['charset'])){
              // user should ensure the database is correctly setup to us utf-8,
              // then use SET NAMES to force charset, SET CHARACTER SET is error-prone.
              mysql_query('SET NAMES "' . $this->cnf['charset'] . '"', $con);
            }
            return true;   // connection and database successfully opened
          } else {
            mysql_close ($con);
            if ($this->cnf['debug'])
              msg("MySQL err: No access to database {$this->cnf['database']}.",-1,__LINE__,__FILE__);
          }
        } else if ($this->cnf['debug'])
          msg ("MySQL err: Connection to {$this->cnf['user']}@{$this->cnf['server']} not possible.",
               -1,__LINE__,__FILE__);

        return false;  // connection failed
      }
      return true;  // connection already open
    }

    //replace mysql.class.php's original function.
    function _addUser($user,$pwd,$name,$mail,$grps){
      if($this->dbcon && is_array($grps)) {
        $sql = str_replace('%{user}', $this->_escape($user),$this->cnf['addUser']);
        $sql = str_replace('%{pass}', $this->_escape($pwd),$sql);
        $sql = str_replace('%{name}', $this->_escape($name),$sql);
        $sql = str_replace('%{email}',$this->_escape($mail),$sql);
        $uid = $this->_modifyDB($sql);

        if ($uid) {
          // set default user in local.php to empty if you don't want to have
          // a default user inserted in additionalGroups when user sign-up
          foreach($grps as $group) {
            if($group == ' ' || $group == '') {
              $gid = true;
            } else {
              $gid = $this->_addUserToGroup($uid, $group, 1);
              if ($gid === false) break;
            }
          }

          if ($gid) return true;
          else {
            /* remove the new user and all group relations if a group can't
             * be assigned. Newly created groups will remain in the database
             * and won't be removed. This might create orphaned groups but
             * is not a big issue so we ignore this problem here.
             */
            $this->_delUser($user);
            if ($this->cnf['debug'])
              msg ("MySQL err: Adding user '$user' to group '$group' failed.",-1,__LINE__,__FILE__);
          }
        }
      }
      return false;
    }

}
?>