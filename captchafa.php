<?php
/**
 * @package     Joomla.Plugin
 * @subpackage  Captcha
 *
 * @copyright   Copyright (C) 2005 - 2013 Open Source Matters, Inc. All rights reserved.
 * @license     GNU General Public License version 2 or later; see LICENSE.txt
 */

defined('_JEXEC') or die;

/**
 * CaptchaFa Plugin.
 * Based on the oficial captcha library( http://captchafa.com/captchafa_php.php )
 *
 * @package     Joomla.Plugin
 * @subpackage  Captcha
 * @since       2.5
 */
class PlgCaptchaCaptchafa extends JPlugin
{
	const CAPTCHAFA_API_SERVER    = "http://www.captchafa.com/api";
	const CAPTCHAFA_VERIFY_SERVER = "www.captchafa.com";

	/**
	 * Load the language file on instantiation.
	 *
	 * @var    boolean
	 * @since  3.1
	 */
	protected $autoloadLanguage = true;

	public function __construct($subject, $config)
	{
		parent::__construct($subject, $config);
		$this->loadLanguage();
	}
	/**
	 * Initialise the captcha
	 *
	 * @param   string	$id	The id of the field.
	 *
	 * @return  Boolean	True on success, false otherwise
	 *
	 * @since  2.5
	 */
	public function onInit($id)
	{
		$pubkey = $this->params->get('public_key', '');

		if ($pubkey == null || $pubkey == '')
		{
			throw new Exception(JText::_('PLG_CAPTCHAFA_ERROR_NO_PUBLIC_KEY'));
		}

		return true;
	}

	/**
	 * Gets the challenge HTML
	 *
	 * @return  string  The HTML to be embedded in the form.
	 *
	 * @since  2.5
	 */
	public function onDisplay($name, $id, $class)
	{
		$document = JFactory::getDocument();
		$style    = '.captchafatable #table { direction: rtl !important; text-align: right !important; top: 20px !important; }';
		$document->addStyleDeclaration($style);

		$pubkey = $this->params->get('public_key', '');
		$server = self::CAPTCHAFA_API_SERVER;

		return '<script type="text/javascript" src="'. $server . '/?challenge&k=' . $pubkey . '"></script>';
	}

	/**
	  * Calls an HTTP POST function to verify if the user's guess was correct
	  *
	  * @return  True if the answer is correct, false otherwise
	  *
	  * @since  2.5
	  */
	public function onCheckAnswer($code)
	{
		$input      = JFactory::getApplication()->input;
		$privatekey = $this->params->get('private_key');
		$remoteip   = $input->server->get('REMOTE_ADDR', '', 'string');
		$challenge  = $input->get('captchafa_challenge_field', '', 'string');
		$response   = $input->get('captchafa_response_field', '', 'string');

		// Check for Private Key
		if (empty($privatekey))
		{
			$this->_subject->setError(JText::_('PLG_CAPTCHAFA_ERROR_NO_PRIVATE_KEY'));
			return false;
		}

		// Check for IP
		if (empty($remoteip))
		{
			$this->_subject->setError(JText::_('PLG_CAPTCHAFA_ERROR_NO_IP'));
			return false;
		}

		// Discard spam submissions
		if ($challenge == null || strlen($challenge) == 0 || $response == null || strlen($response) == 0)
		{
			$this->_subject->setError(JText::_('PLG_CAPTCHAFA_ERROR_EMPTY_SOLUTION'));
			return false;
		}

		$response = $this->_captchafa_http_post(
			self::CAPTCHAFA_VERIFY_SERVER, "/api/verify/",
			array(
				'privatekey' => $privatekey,
				'remoteip'   => $remoteip,
				'challenge'  => $challenge,
				'response'   => $response
			)
		);

		$answers = explode("\n", $response[1]);

		if (trim($answers[0]) == 'true')
		{
			return true;
		}
		else
		{
			if($answers[0] == 'invalid query! please retry')
			{
				$answers[1] = 'INVALID-REQUEST-COOKIE';
			}

			switch($answers[1])
			{
				case 'کد وارد شده ا': $answers[1] = 'INCORRECT-CAPTCHA-SOL';
			}

			//@todo use exceptions here
			$this->_subject->setError(JText::_('PLG_CAPTCHAFA_ERROR_'.strtoupper(str_replace('-', '_', $answers[1]))));
			return false;
		}
	}

	/**
	 * Encodes the given data into a query string format.
	 *
	 * @param   string  $data  Array of string elements to be encoded
	 *
	 * @return  string  Encoded request
	 *
	 * @since  2.5
	 */
	private function _captchafa_qsencode($data)
	{
		$req = "";
		foreach ($data as $key => $value)
		{
			$req .= $key . '=' . urlencode(stripslashes($value)) . '&';
		}

		// Cut the last '&'
		$req = rtrim($req, '&');
		return $req;
	}

	/**
	 * Submits an HTTP POST to a CAPTCHAfa server.
	 *
	 * @param   string  $host
	 * @param   string  $path
	 * @param   array   $data
	 * @param   int     $port
	 *
	 * @return  array   Response
	 *
	 * @since  2.5
	 */
	private function _captchafa_http_post($host, $path, $data, $port = 80)
	{
		$req = $this->_captchafa_qsencode($data);

		$http_request  = "POST $path HTTP/1.0\r\n";
		$http_request .= "Host: $host\r\n";
		$http_request .= "Content-Type: application/x-www-form-urlencoded;\r\n";
		$http_request .= "Content-Length: " . strlen($req) . "\r\n";
		$http_request .= "User-Agent: CAPTCHAfa/PHP\r\n";
		$http_request .= "\r\n";
		$http_request .= $req;

		$response = '';
		if (($fs = @fsockopen($host, $port, $errno, $errstr, 10)) == false )
		{
			die('Could not open socket');
		}

		fwrite($fs, $http_request);

		while (!feof($fs))
		{
			// One TCP-IP packet
			$response .= fgets($fs, 1160);
		}

		fclose($fs);
		$response = explode("\r\n\r\n", $response, 2);

		return $response;
	}
}
