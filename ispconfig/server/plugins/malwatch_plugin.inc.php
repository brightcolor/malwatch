<?php

/**
 * Starts a scan when the interface queues one.
 *
 * The plugin only launches the scanner and returns. It never waits for it:
 * a scan over a large web root takes minutes to hours, and server.php
 * processes the datalog serially - waiting here would stall every other
 * ISPConfig task on the machine. The cron class collects the result.
 */
class malwatch_plugin
{
	var $plugin_name = 'malwatch_plugin';
	var $class_name = 'malwatch_plugin';

	public function onInstall()
	{
		global $conf;
		return $conf['services']['web'] == true;
	}

	public function onLoad()
	{
		global $app;
		$app->plugins->registerEvent('malwatch_job_insert', $this->plugin_name, 'job_insert');
	}

	public function job_insert($event_name, $data)
	{
		global $app, $conf;

		if (intval($data['new']['server_id']) != intval($conf['server_id'])) {
			return;
		}

		$app->uses('malwatch_helper,malwatch_runner');

		$job_id = intval($data['new']['job_id']);
		$job = $app->dbmaster->queryOneRecord('SELECT * FROM malwatch_job WHERE job_id = ?', $job_id);
		if (!is_array($job) || $job['job_status'] !== 'pending') {
			return;
		}

		// Claim the row before doing anything. A second datalog pass over the
		// same insert would otherwise start the scanner twice on one tree.
		if (!$app->malwatch_helper->claim_job($job_id)) {
			return;
		}

		$config = $app->malwatch_helper->get_config();
		$running = $app->malwatch_helper->count_running_jobs($job_id);
		if ($running >= max(1, intval($config['max_parallel']))) {
			// Too many at once would drown the machine in IO. The job goes
			// back to pending and the cron class picks it up when there is room.
			$app->malwatch_helper->release_job($job_id, 'Warten: es laufen bereits ' . $running . ' Prüfungen.');
			return;
		}

		$app->malwatch_runner->start($job, $config);
	}
}
