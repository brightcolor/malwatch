<?php

/**
 * Raises events for changes to the malwatch job table, so the server plugin
 * learns about a scan the interface requested.
 */
class malwatch_module
{
	var $module_name = 'malwatch_module';
	var $class_name = 'malwatch_module';
	var $actions_available = array(
		'malwatch_job_insert',
		'malwatch_job_update',
		'malwatch_job_delete'
	);

	function onInstall()
	{
		global $conf;
		return $conf['services']['web'] == true;
	}

	function onLoad()
	{
		global $app;
		$app->plugins->announceEvents($this->module_name, $this->actions_available);
		$app->modules->registerTableHook('malwatch_job', 'malwatch_module', 'process');
	}

	function process($tablename, $action, $data)
	{
		global $app;

		if ($tablename !== 'malwatch_job') {
			return;
		}
		if ($action == 'i') {
			$app->plugins->raiseEvent('malwatch_job_insert', $data);
		}
		if ($action == 'u') {
			$app->plugins->raiseEvent('malwatch_job_update', $data);
		}
		if ($action == 'd') {
			$app->plugins->raiseEvent('malwatch_job_delete', $data);
		}
	}
}
