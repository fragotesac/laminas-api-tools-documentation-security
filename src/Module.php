<?php

namespace LaminasApiToolsDocumentationSecurity;

use Laminas\EventManager\EventInterface;
use Laminas\Http\Response;
use Laminas\Mvc\MvcEvent;

class Module
{
    public function onBootstrap(EventInterface $e)
    {
        $app       = $e->getApplication();
        $events    = $app->getEventManager();
        // ApiTools Documentation
        $events->attach(MvcEvent::EVENT_ROUTE, function(MvcEvent $event) use ($e) {
            $request = $event->getRequest();
            $headers = $request->getHeaders();

            $path = $request->getUri()->getPath();
            if ('/api-tools/documentation' == $path) {
                if (!$headers->has('Authorization')) {
                    return $this->documentationUnauthorizedResponse($event);
                }

                $authHeader = $request->getHeaders()->get('Authorization')->getFieldValue();
                list($type, $credentials) = explode(' ', $authHeader);

                if (strtolower($type) !== 'basic' || !$this->isValidCredentials($credentials, $e)) {
                    return $this->documentationUnauthorizedResponse($event);
                }
            }
        });
    }


    private function isValidCredentials(string $credentials, EventInterface $e)
    {
        $decodedCredentials = base64_decode($credentials);
        list($username, $password) = explode(':', $decodedCredentials);
        $configInfo = $e->getTarget()->getServiceManager()->get('config');

        if (!empty($configInfo['api-tools-mvc-auth']) && !empty($configInfo['api-tools-mvc-auth']['authentication'])) {
            foreach ($configInfo['api-tools-mvc-auth']['authentication']['adapters'] as $adapter) {
                // @todo extend this to other adapters
                if (!empty($adapter['options']) && !empty($adapter['options']['htpasswd'])) {
                    $lines = file($adapter['options']['htpasswd'], FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
                    foreach ($lines as $line) {
                        list($fileUsername, $fileHash) = explode(':', $line, 2);
                        // Check if the username matches
                        if ($fileUsername === $username) {
                            // Check the hash prefix and verify accordingly
                            if (strpos($fileHash, '{SHA}') === 0) {
                                $hash = substr($fileHash, 5);
                                $decodedHash = base64_decode($hash);
                                $hashedPassword = sha1($password, true); // true for raw output

                                return $hashedPassword === $decodedHash;
                            } elseif (password_verify($password, $fileHash)) {
                                // For bcrypt hashes (or other supported by password_verify)
                                return true;
                            }
                        }
                    }
                }
            }
        }

        return false;
    }

    private function documentationUnauthorizedResponse(MvcEvent $event)
    {
        $response = $event->getResponse();
        $response->setStatusCode(Response::STATUS_CODE_401);
        $response->getHeaders()->addHeaderLine('WWW-Authenticate', 'Basic realm="Documentation"');

        return $response;
    }

	public function getConfig()
	{
		return include __DIR__ . '/../config/module.config.php';
	}
}
