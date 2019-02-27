<?php

use SilverStripe\Control\Email\Email;
use SilverStripe\Control\Email\Mailer;
use SilverStripe\Core\Convert;
use SilverStripe\Core\Injector\Injector;

require_once 'Crypt/GPG.php';

/**
 * Mailer that encrypts contents of email using GPG. Encrypting HTML is not implemented, quite difficult and requires
 * a very simple HTML template that can be encrypted and re-wrapped in body tags.
 *
 * Necessary to provide keyring files via Crypt_GPG options in YAML.
 *
 * @todo  HTML encryption if possible, look into PGP/MIME
 * @todo  Ability to add additional encryption and signing keys
 * @todo  correct headers for Content-Transfer-Encoding, should be base64 for ASCII armor? Only accepts binary|8bit|7bit not quoted-printable|base64
 *        http://en.wikipedia.org/wiki/MIME#Content-Transfer-Encoding
 *        http://www.techopedia.com/definition/23150/ascii-armor
 *        https://tools.ietf.org/html/rfc3156
 *        http://docs.roguewave.com/sourcepro/11.1/html/protocolsug/10-1.html
 *        https://www.gnupg.org/documentation/manuals/gnupg/Input-and-Output.html
 *        'Base64 is a group of similar binary-to-text encoding schemes that represent binary data in an ASCII string format by translating it into a radix-64 representation.'
 * @todo  Content-Type header to include protocol='application/pgp-encrypted' https://tools.ietf.org/html/rfc3156
 *
 */
class GPGMailer Extends Email
{
    /**
     * Options for Crypt_GPG
     *
     * @see Crypt_GPGAbstract::__construct() for available options
     * @var array
     */
    private $options = array();
    /**
     * Instance of Crypt_GPG
     *
     * @var Crypt_GPG
     */
    private $gpg;
    /**
     * Whether to sign the email also
     *
     * @var boolean
     */
    private $sign = false;

    /**
     * Set options for Crypt_GPG and add encrypting and signing keys.
     *
     * @param string $encryptKey Key identifier, usually an email address but can be fingerprint
     * @param string $signKey Key identifier, usually an email address but can be fingerprint
     * @param string $signKeyPassphrase Optional passphrase for key required for signing
     */
    public function __construct($encryptKey = null, $signKey = null, $signKeyPassphrase = null)
    {
        parent::__construct();

        // Set options
        $this->setOptions();
        $this->gpg = new Crypt_GPG($this->options);
        // Add encryption key
        if (is_null($encryptKey) && !defined('GPGMAILER_ENCRYPT_KEY')) {
            throw new InvalidArgumentException('$encryptKey not defined');
        }
        $this->gpg->addEncryptKey($encryptKey ?: GPGMAILER_ENCRYPT_KEY);
        // Add signing key
        if ($signKey || defined('GPGMAILER_SIGN_KEY')) {
            if (is_null($signKeyPassphrase) && defined('GPGMAILER_SIGN_KEY_PASSPHRASE')) {
                $signKeyPassphrase = GPGMAILER_SIGN_KEY_PASSPHRASE;
            }
            $this->gpg->addSignKey($signKey ?: GPGMAILER_SIGN_KEY, $signKeyPassphrase);
            $this->sign = true;
        }
    }

    /**
     * Set options for Crypt_GPG.
     *
     * @see Crypt_GPGAbstract::__construct() for available options
     */
    private function setOptions()
    {
        //$options = GPGMailer::config()->options;
        //if (isset($options[0]) && is_array($options[0])) {
        //    $this->options = $options[0];
        //}
        //// Option to override home dir and provide a relative path instead
        //if (isset($this->options['relative_homedir'])) {
        //    $this->options['homedir'] = Director::getAbsFile($this->options['relative_homedir']);
        //    unset($this->options['relative_homedir']);
        //}
        //// Environment variables should override Configuration system
        //if (defined('GPGMAILER_HOMEDIR')) {
        //    $this->options['homedir'] = GPGMAILER_HOMEDIR;
        //}
    }

    public function send()
    {
        $this->sendPlain();
    }

    public function sendPlain()
    {
        // If the subject line contains extended characters, we must encode it
        $subject = Convert::xml2raw($this->getSwiftMessage()->getSubject());
        $this->getSwiftMessage()->setSubject('=?UTF-8?B?' . base64_encode($subject) . '?=');

        $this->getSwiftMessage()->setMaxLineLength(0);

        $this->getSwiftMessage()->setContentType('text/plain');

        $plainEncoder = new Swift_Mime_ContentEncoder_PlainContentEncoder('7bit');

        $this->getSwiftMessage()->setEncoder($plainEncoder);

        // GPG encryption and signing if necessary
        if ($this->sign) {
            $plainContent = $this->gpg->encryptAndSign($this->getSwiftMessage()->getBody());
        }else {
            $plainContent = $this->gpg->encrypt($this->getSwiftMessage()->getBody());
        }

        $this->getSwiftMessage()->setBody($plainContent);

        return Injector::inst()->get(Mailer::class)->send($this);
    }

    /**
     * @param string $file
     * @param null $destFileName
     * @param null $mime
     * @return $this|void
     */
    public function addAttachment($file, $destFileName = null, $mime = null)
    {
        if (!$file) {
            user_error('encodeFileForEmail: not passed a filename and/or data', E_USER_WARNING);
            return;
        }
        if (is_string($file)) {
            $file = array('filename' => $file);
            $fh = fopen($file['filename'], 'rb');
            if ($fh) {
                $file['contents'] = '';
                while (!feof($fh)) {
                    $file['contents'] .= fread($fh, 10000);
                }
                fclose($fh);
            }
        }
        // Build headers, including content type
        if (!$destFileName) {
            $base = basename($file['filename']);
        }else {
            $base = $destFileName;
        }

        // Force base and MIME type for encrypted attachements
        $base = $base . '.pgp';
        $mimeType = 'application/octet-stream';

        // GPG encryption and signing if necessary
        if ($this->sign) {
            $file['contents'] = $this->gpg->encryptAndSign($file['contents']);
        }else {
            $file['contents'] = $this->gpg->encrypt($file['contents']);
        }

        //$this->getSwiftMessage()->getHeaders()->addTextHeader('Content-Disposition', 'attatchment;\n\tfilename=\'$base\'\n');
        //$this->getSwiftMessage()->getHeaders()->addTextHeader('Content-Description', 'encrypted data');

        $attachment = \Swift_Attachment::newInstance($file['contents'], $base, $mimeType . ";\n\tname='$base'\n");

        $this->getSwiftMessage()->attach($attachment);

        return $this;
    }

    /**
     * Encrypting HTML emails does not work so this method triggers a warning and sends using sendPlain() and plaintext
     * version of the HTML content.
     *
     * @return mixed Array if successful or false if unsuccessful
     */
    public function sendHTML()
    {
        // HTML emails cannot be encrypted and create a number of issues, sendPlain() should be used instead
        trigger_error('HTML email content cannot be encrypted, only the plain text component of this email will be generated.', E_USER_WARNING);
        $this->setBody(Convert::xml2raw($this->getBody()));

        return $this->sendPlain();
    }
}