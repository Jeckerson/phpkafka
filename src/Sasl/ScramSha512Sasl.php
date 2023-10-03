<?php

declare(strict_types=1);

namespace longlang\phpkafka\Sasl;

use Fabiang\Sasl\Authentication\AuthenticationInterface;
use Fabiang\Sasl\Sasl;
use longlang\phpkafka\Config\CommonConfig;
use longlang\phpkafka\Exception\KafkaErrorException;

class ScramSha512Sasl implements SaslInterface
{
    private AuthenticationInterface $factory;

    protected CommonConfig $config;

    /**
     * @throws KafkaErrorException
     */
    public function __construct(CommonConfig $config)
    {
        $this->config = $config;
        $config = $this->config->getSasl();
        if (empty($config['username']) || empty($config['password'])) {
            throw new KafkaErrorException('sasl not found auth info');
        }

        $this->factory = (new Sasl())->factory($this->getName(), [
            'authcid' => $config['username'],
            'secret' => $config['password'],
        ]);
    }

    public function getName(): string
    {
        return 'SCRAM-SHA-512';
    }

    public function getAuthBytes(?string $challenge = null): string
    {
        return $this->factory->createResponse($challenge);
    }

    public function hasChallenge(): bool
    {
        return true;
    }
}
