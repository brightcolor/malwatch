<?php

/**
 * Konfiguration des Moduls "Security".
 *
 * Frueher hing das Addon als Navigationsgruppe in der Seitenleiste des
 * Sites-Moduls, weil ein eigenes Modul in sys_user.modules jedes Bedieners
 * eingetragen werden muss und das Kerndaten anfasst. Das erledigt jetzt der
 * Installer - denselben Weg geht wpinstaller auf demselben Server.
 */

$module['name']      = 'security';
$module['title']     = 'Security';
$module['template']  = 'module.tpl.htm';
$module['startpage'] = 'security/status.php';
$module['tab_width'] = '';
$module['order']     = '40';
$module['icon']      = 'icon icon-monitor';

$items = array();

$items[] = array(
	'title'   => 'Status',
	'target'  => 'content',
	'link'    => 'security/status.php',
	'html_id' => 'security_status'
);

// Die Fundliste ist die einzige Ansicht, die ueber die Grenze einer Website
// hinweg sieht. Die Detailseite zeigt die Funde EINER Website; wer wissen
// will, wo dieselbe Regel sonst noch angeschlagen hat - eine Infektionswelle
// trifft selten nur einen Kunden -, filtert hier nach Regel, Pfad oder Stufe.
// Die Seite, ihre Vorlage, ihre Listendefinition und vier Sprachdateien werden
// ohnehin installiert; ohne diesen Eintrag war sie nur nicht mehr erreichbar,
// seit die alte Menuedatei entfallen ist.
$items[] = array(
	'title'   => 'Funde',
	'target'  => 'content',
	'link'    => 'security/malwatch_finding_list.php',
	'html_id' => 'security_findings'
);

$items[] = array(
	'title'   => 'Quarantäne',
	'target'  => 'content',
	'link'    => 'security/malwatch_quarantine_list.php',
	'html_id' => 'security_quarantine'
);

$items[] = array(
	'title'   => 'Prüfläufe',
	'target'  => 'content',
	'link'    => 'security/malwatch_scan_list.php',
	'html_id' => 'security_scans'
);

$items[] = array(
	'title'   => 'Einstellungen',
	'target'  => 'content',
	'link'    => 'security/malwatch_config_edit.php',
	'html_id' => 'security_settings'
);

$module['nav'][] = array(
	'title' => 'Security',
	'open'  => 1,
	'items' => $items
);

unset($items);
