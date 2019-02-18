<?php

namespace Hybridauth\Provider;

use Hybridauth\Adapter\OAuth2;
use Hybridauth\Exception\Exception;
use Hybridauth\Data\Collection;
use Hybridauth\User\Profile;
use Hybridauth\Data;

class Inp extends OAuth2
{
    protected $apiBaseUrl = 'http://api.nonprofititalia.it/';
    protected $authorizeUrl = 'http://nonprofititalia.it/auth.html';
    protected $accessTokenUrl = 'http://api.nonprofititalia.it/tokens.json';

    /**
     * @return bool|Profile
     * @throws Exception
     * @throws \Hybridauth\Exception\HttpClientFailureException
     * @throws \Hybridauth\Exception\HttpRequestFailedException
     * @throws \Hybridauth\Exception\InvalidAccessTokenException
     */
    function getUserProfile()
    {
        $accessToken = $this->getAccessToken();
        $response = $this->httpClient->request($this->apiBaseUrl."userinfo.json","POST",array(
            'access_token'=>$accessToken['access_token']
        ),
            array('Content-Type'=>'application/x-www-form-urlencoded')
        );
        $this->validateApiResponse('Signed API request has returned an error');

        $response = (new Data\Parser())->parse($response);

        $data = new Collection($response);


        $userProfile = new Profile();
        $userProfile->identifier = $data->get('email');
        $userProfile->email = $data->get('email');
        $userProfile->displayName = $data->get('fullname');
        $userProfile->data = $data->toArray();

        return $userProfile;
    }

}

