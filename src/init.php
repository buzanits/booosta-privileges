<?php
namespace booosta\privileges;

\booosta\Framework::add_module_trait('webapp', 'privileges\webapp');
\booosta\Framework::add_module_trait('genericuser', 'privileges\genericuser');

trait Webapp
{
  protected $auth_actions = false, $privs;
  protected $simple_userfield;

  public function set_priv($action, $priv) 
  { 
    if($action == 'all') $action = ['view', 'create', 'edit', 'delete'];

    if(is_array($action))
      foreach($action as $act)
        $this->privs[$act] = $priv;
    else
      $this->privs[$action] = $priv; 
  }

  protected function auth($action)
  {
    if(!isset($this->privs[$action])) $this->privs[$action] = "$action $this->name";

    $result = $this->before_auth($action);
    if(is_bool($result)) return $result;

    if($this->auth_actions === false) return true;
    $user = $this->get_user();
    if(!is_object($user)) return false;
    if(!$user->is_valid()) return false;

    $has_privilege = $user->has_privilege($this->privs[$action]);
    if(strstr($has_privilege, 'ERROR')) $this->raise_error($has_privilege);

    if($has_privilege === true) return true;
    $this->raise_error('ERROR: missing privilege ' . $this->privs[$action]);
  }

  protected function before_auth($action) { return null; }

  protected function user_has_privilege($priv)
  {
    if(!is_object($this->user)) return false;
    return $this->user->has_privilege($priv);
  }

  protected function apply_userfield($action, $param = null)
  {
    $uf = $this->use_userfield;
    if($uf == '') return;
    #\booosta\debug($uf);

    // You can provide an object with the userfield functions
    if(is_object($uf)) return $this->apply_userfield_obj($action, $param);

    switch($action):
    case 'init':
      $this->add_default_clause("$uf='$this->user_id'");
    break;
    case 'new':
      if(is_object($param)) $param->set($uf, $this->user_id);
    break;
    case 'edit':
      if(is_object($param) && $param->get($uf) != $this->user_id && !strstr($uf, ',')) $this->raise_error("Illegal value for field '$uf'");
      // intentionally no break
    case 'action edit':
    case 'delete':
      // use $this->use_userfield = 'subfield>subtable,user';  when subfield points to subtable that has field 'user'
      if(strstr($uf, ',')):
        $levels = explode(',', $uf);
        $uobj = $param;
        if(!is_object($uobj)) $uobj = $this->get_dbobject();
  
        while(sizeof($levels)):
          $currentfield = array_shift($levels);
          if(!is_object($uobj) || !$uobj->is_valid()) $this->raise_error("apply_userfield: uobj not found for '$currentfield', subtable $subtable");

          list($subfield, $subtable) = explode('>', $currentfield);
          if($subtable == '') $subtable = $subfield;
  
          $subvalue = $uobj->get($subfield);
          $uobj = $this->getDataobject($subtable, $subvalue);
        endwhile;

        $owner_id = $uobj->get('id');  // $uobj must be the user data object
        if($owner_id != $this->user_id) $this->raise_error("Missing privilege to access object $this->id");;
      else:
        $obj = $this->get_dbobject();
        if($obj->get($uf) != $this->user_id) $this->raise_error("Missing privilege to access object $this->id");
      endif;
    break;

    case 'sub:new':
      if(is_object($param) && is_array($uf)):
        if($uf['supertable'] != '' && $uf['superfield'] == '') $uf['superfield'] = $uf['supertable'];
        if($uf['superfield'] != '' && $uf['supertable'] == '') $uf['supertable'] = $uf['superfield'];

        $superobj = $this->getDataobject($uf['supertable'], $param->get($uf['superfield']));
        if(is_object($superobj) && $superobj->get($uf['userfield']) != $this->user_id) 
          $this->raise_error('Missing privilege to access object ' . $superobj->get($uf['userfield']));;
      else:
        $this->apply_userfield('new', $param);
      endif;
    break;
    case 'sub:edit':
      if(is_object($param) && is_array($uf)):
        if($uf['supertable'] != '' && $uf['superfield'] == '') $uf['superfield'] = $uf['supertable'];
        if($uf['superfield'] != '' && $uf['supertable'] == '') $uf['supertable'] = $uf['superfield'];

        $superobj = $this->getDataobject($uf['supertable'], $param->get($uf['superfield']));
        if(is_object($superobj) && $superobj->get($uf['userfield']) != $this->user_id) 
          $this->raise_error("Illegal value for field '{$uf['superfield']}'");;
      else:
        $this->apply_userfield('edit', $param);
      endif;
    case 'sub:action edit':
    case 'sub:delete':
      if(is_array($uf)):
        if($uf['supertable'] != '' && $uf['superfield'] == '') $uf['superfield'] = $uf['supertable'];
        if($uf['superfield'] != '' && $uf['supertable'] == '') $uf['supertable'] = $uf['superfield'];

        $obj = $this->get_dbobject();
        $superobj = $this->getDataobject($uf['supertable'], $obj->get($uf['superfield']));
        if(is_object($superobj) && $superobj->get($uf['userfield']) != $this->user_id) 
          $this->raise_error('Missing privilege to access object');;
      else:
        $this->apply_userfield('delete', $param);
      endif;
    break;
    endswitch;
  } 

  protected function apply_userfield_obj($action, $param = null)
  {
    $uf = $this->use_userfield;
    if(!is_object($uf)) $this->raise_error('No object provided to apply_userfield_obj()');
    #\booosta\debug("action: $action");

    switch($action):
    case 'init': $uf->init($param); break;
    case 'action default': $uf->action_default($param); break;
    case 'new': $uf->add($param); break;
    case 'edit': $uf->edit($param); break;
    case 'action edit': $uf->action_edit($param); break;
    case 'delete': $uf->delete($param); break;
    case 'action subtables': $uf->action_subtables($param); break;
    case 'sub:new': $uf->sub_new($param); break;
    case 'sub:edit': $uf->sub_edit($param); break;
    case 'sub:action edit': $uf->sub_action_edit($param); break;
    case 'sub:delete': $uf->sub_delete($param); break;
    default: $uf->$action($param); break;
    endswitch;
  }
}

class Userfield
{
  protected $obj, $dbobj;
  protected $fieldname, $fieldval;

  public function __construct($webapp_obj)
  {
    $this->obj = $webapp_obj;
    $this->dbobj = $webapp_obj->get_dbobject();
    $this->init();
  }

  public function __call($name, $args)
  {
    if(method_exists($this, $name)) call_user_func_array($name, $args);
  }

  public function action_default($param)
  {
    $this->obj->add_default_clause("`$this->fieldname`='{$this->fieldval}'");
  }

  public function add($param)
  {
    if(is_object($param)) $param->set($this->fieldname, $this->fieldval);
  }

  public function edit($param)
  {
    if(is_object($param) && $param->get($this->fieldname) != $this->fieldval)
      $this->obj->raise_error('Fehlende Berechtigung zum Zugriff auf das Objekt');
  }

  protected function proc_action($param)
  {
    #\booosta\debug('is_object: ' . is_object($this->dbobj)); if(is_object($this->dbobj)) \booosta\debug('fieldname: ' . $this->dbobj->get($this->fieldname)); \booosta\debug('fieldval: ' . $this->fieldval);
    $this->check_dbobj();
    if(!is_object($this->dbobj)) return false;
    if($this->dbobj->get($this->fieldname) != $this->fieldval) $this->obj->raise_error('Fehlende Berechtigung zum Zugriff auf das Objekt!');
  }

  protected function check_dbobj()
  {
    if(!is_object($this->dbobj) && is_object($this->obj)) $this->dbobj = $this->obj->get_dbobject();
  }

  public function action_edit($param) { $this->proc_action($param); }
  public function delete($param) { $this->proc_action($param); }
  public function action_subtables($param) { $this->proc_action($param); }
}

trait Genericuser
{
  public $privileges;

  protected function make_privileges() { return $this->makeInstance('DB_Privileges'); }

  protected function get_all_privileges()
  {
    $privileges = $this->get_privileges();

    $roles = array_keys($this->get_roles());
    foreach($roles as $role):
      #print "<br>role: $role<br>";
      $roleprivs = $this->privileges->get_all_role_privileges($role);
      #print_r($roleprivs);
      if(strstr(print_r($roleprivs, true), 'ERROR')) return $roleprivs;

      $privileges = array_merge($privileges, $roleprivs);
    endforeach;

    return array_unique($privileges);
  }

  protected function get_privileges()
  {
    return $this->privileges->get_user_privileges($this->id);
  }

  public function get_roles()
  {
    return $this->privileges->get_user_roles($this->id);
  }

  public function has_privilege($privilege_name)
  {
    $this->init_db();
    $privilege_id = $this->get_privilege_id($privilege_name);
    $allprivs = $this->get_all_privileges();
    if(strstr(print_r($allprivs, true), 'ERROR')) return $allprivs;

    #print "pn: $privilege_name"; print_r($allprivs);
    return in_array($privilege_id, $allprivs);
  }

  public function has_role($role_name)
  {
    $this->init_db();
    $role_id = $this->get_role_id($role_name);
    $allroles = $this->get_roles();
    if(strstr(print_r($allroles, true), 'ERROR')) return $allroles;

    return in_array($role_id, $allroles);
  }
}
